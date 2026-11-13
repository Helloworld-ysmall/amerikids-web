const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Server } = require('socket.io');

const CONTROLLER_SESSION_COOKIE = 'amerikids_controller_session';
const CONTROLLER_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_STUN_URLS = ['stun:stun.l.google.com:19302'];

function normalizeUrlList(value, fallback = []) {
  const values = Array.isArray(value)
    ? value
    : typeof value === 'string'
      ? value.split(',')
      : fallback;
  return values
    .map((url) => String(url).trim())
    .filter(Boolean);
}

function loadConfig(env = process.env) {
  if (!['development', 'production', 'test'].includes(env.NODE_ENV)) {
    throw new Error('NODE_ENV must be set to development, test, or production.');
  }

  const required = ['SESSION_CODE', 'DEVICE_TOKEN', 'CONTROLLER_TOKEN'];
  const missing = required.filter((name) => !env[name]);
  if (missing.length > 0) {
    throw new Error(`Missing required environment variable(s): ${missing.join(', ')}`);
  }
  if (env.NODE_ENV === 'production') {
    const secretNames = ['DEVICE_TOKEN', 'CONTROLLER_TOKEN'];
    if (env.TURN_SHARED_SECRET) secretNames.push('TURN_SHARED_SECRET');
    const weakSecrets = secretNames
      .filter((name) => env[name].length < 32);
    if (weakSecrets.length > 0) {
      throw new Error(`Production secrets must be at least 32 characters: ${weakSecrets.join(', ')}`);
    }
  }

  const turnUrls = normalizeUrlList(env.TURN_URLS);
  if (turnUrls.length > 0 && !env.TURN_SHARED_SECRET) {
    throw new Error('TURN_SHARED_SECRET is required when TURN_URLS is configured.');
  }

  const turnCredentialTtlSeconds = Number(env.TURN_CREDENTIAL_TTL_SECONDS || 3600);
  if (!Number.isInteger(turnCredentialTtlSeconds) || turnCredentialTtlSeconds < 60) {
    throw new Error('TURN_CREDENTIAL_TTL_SECONDS must be an integer of at least 60.');
  }

  return {
    sessionCode: env.SESSION_CODE,
    deviceToken: env.DEVICE_TOKEN,
    controllerToken: env.CONTROLLER_TOKEN,
    stunUrls: normalizeUrlList(env.STUN_URLS, DEFAULT_STUN_URLS),
    turnUrls,
    turnSharedSecret: env.TURN_SHARED_SECRET || '',
    turnCredentialTtlSeconds,
    production: env.NODE_ENV === 'production',
    port: Number(env.PORT || 3000),
  };
}

function getCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  for (const cookie of cookieHeader.split(';')) {
    const separator = cookie.indexOf('=');
    if (separator >= 0 && cookie.slice(0, separator).trim() === name) {
      return cookie.slice(separator + 1).trim();
    }
  }
  return null;
}

function isControllerSessionValid(sessions, sessionId) {
  const expiresAt = sessionId && sessions.get(sessionId);
  if (!expiresAt) return false;
  if (expiresAt <= Date.now()) {
    sessions.delete(sessionId);
    return false;
  }
  return true;
}

function sendJson(response, status, value) {
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
  });
  response.end(JSON.stringify(value));
}

function secureEquals(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length &&
    crypto.timingSafeEqual(leftBytes, rightBytes);
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    let complete = false;
    request.on('data', (chunk) => {
      if (complete) return;
      size += chunk.length;
      if (size > 4096) {
        complete = true;
        reject(Object.assign(new Error('Request body is too large.'), { statusCode: 413 }));
        request.resume();
        return;
      }
      body += chunk.toString('utf8');
    });
    request.on('end', () => {
      if (complete) return;
      try {
        resolve(JSON.parse(body));
      } catch (error) {
        reject(error);
      }
    });
    request.on('error', (error) => {
      if (!complete) reject(error);
    });
  });
}

function createIceServers(config) {
  const normalizedConfig = {
    stunUrls: normalizeUrlList(config && config.stunUrls, DEFAULT_STUN_URLS),
    turnUrls: normalizeUrlList(config && config.turnUrls),
    turnSharedSecret: String(config && config.turnSharedSecret || ''),
    turnCredentialTtlSeconds: Number.isInteger(Number(config && config.turnCredentialTtlSeconds))
      ? Number(config.turnCredentialTtlSeconds)
      : 3600,
  };

  const iceServers = normalizedConfig.stunUrls.map((urls) => ({ urls }));
  if (normalizedConfig.turnUrls.length === 0) return iceServers;

  const expiresAt = Math.floor(Date.now() / 1000) + normalizedConfig.turnCredentialTtlSeconds;
  const username = `${expiresAt}:amerikids`;
  const credential = crypto
    .createHmac('sha1', normalizedConfig.turnSharedSecret)
    .update(username)
    .digest('base64');
  iceServers.push({
    urls: normalizedConfig.turnUrls,
    username,
    credential,
    credentialType: 'password',
  });
  return iceServers;
}

function createServer(config = {}) {
  const normalizedConfig = {
    sessionCode: String(config.sessionCode || 'amerikids-room'),
    deviceToken: String(config.deviceToken || ''),
    controllerToken: String(config.controllerToken || ''),
    stunUrls: normalizeUrlList(config.stunUrls, DEFAULT_STUN_URLS),
    turnUrls: normalizeUrlList(config.turnUrls),
    turnSharedSecret: String(config.turnSharedSecret || ''),
    turnCredentialTtlSeconds: Number.isInteger(Number(config.turnCredentialTtlSeconds))
      ? Number(config.turnCredentialTtlSeconds)
      : 3600,
    production: Boolean(config.production),
    port: Number.isInteger(Number(config.port)) ? Number(config.port) : 3000,
  };
  const controllerSessions = new Map();
  const httpServer = http.createServer(async (request, response) => {
    const requestUrl = new URL(request.url, 'http://localhost');

    if (request.method === 'GET' && requestUrl.pathname === '/') {
      response.writeHead(200, {
        'Cache-Control': 'no-store',
        'Content-Type': 'text/plain; charset=utf-8',
      });
      response.end('AmeriKIDS WebRTC Signaling Server is Running!');
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname === '/health') {
      sendJson(response, 200, { status: 'ok' });
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/session/login') {
      const origin = request.headers.origin;
      const requestHost = (request.headers['x-forwarded-host'] || request.headers.host || '')
        .split(',')[0]
        .trim();
      if (!origin) {
        sendJson(response, 403, { error: 'Request origin is required.' });
        return;
      }
      let originHost;
      try {
        originHost = new URL(origin).host;
      } catch {
        sendJson(response, 403, { error: 'Invalid request origin.' });
        return;
      }
      if (originHost !== requestHost) {
        sendJson(response, 403, { error: 'Cross-origin sign-in is not allowed.' });
        return;
      }
      if (!String(request.headers['content-type'] || '').startsWith('application/json')) {
        sendJson(response, 415, { error: 'Expected a JSON request.' });
        return;
      }

      let credentials;
      try {
        credentials = await readJsonBody(request);
      } catch (error) {
        if (error.statusCode !== 413 && !(error instanceof SyntaxError)) {
          console.error('Unable to read controller sign-in request:', error);
        }
        sendJson(response, error.statusCode || 400, {
          error: error.statusCode === 413 ? error.message : 'Invalid sign-in request.',
        });
        return;
      }

      if (!credentials || !secureEquals(credentials.token, normalizedConfig.controllerToken)) {
        sendJson(response, 401, { error: 'Invalid controller token.' });
        return;
      }

      const sessionId = crypto.randomBytes(32).toString('base64url');
      const expiresAt = Date.now() + CONTROLLER_SESSION_TTL_MS;
      for (const [existingId, existingExpiry] of controllerSessions) {
        if (existingExpiry <= Date.now()) controllerSessions.delete(existingId);
      }
      controllerSessions.set(sessionId, expiresAt);
      const forwardedProto = String(request.headers['x-forwarded-proto'] || '')
        .split(',')[0]
        .trim();
      const secureCookie = normalizedConfig.production || request.socket.encrypted || forwardedProto === 'https';
      response.writeHead(204, {
        'Cache-Control': 'no-store',
        'Set-Cookie': `${CONTROLLER_SESSION_COOKIE}=${sessionId}; Max-Age=${CONTROLLER_SESSION_TTL_MS / 1000}; Path=/; HttpOnly; SameSite=Strict${secureCookie ? '; Secure' : ''}`,
      });
      response.end();
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname === '/session') {
      const sessionId = getCookie(request.headers.cookie, CONTROLLER_SESSION_COOKIE);
      if (isControllerSessionValid(controllerSessions, sessionId)) {
        response.writeHead(204, { 'Cache-Control': 'no-store' });
        response.end();
      } else {
        sendJson(response, 401, { error: 'Controller sign-in required.' });
      }
      return;
    }

    if (request.method !== 'GET') {
      response.writeHead(405, { Allow: 'GET' });
      response.end('Method Not Allowed');
      return;
    }

    if (requestUrl.pathname !== '/controller') {
      response.writeHead(404);
      response.end('Not Found');
      return;
    }

    const controllerTemplatePath = path.join(__dirname, 'controller.html');
    const fallbackTemplatePath = path.join(__dirname, 'index.html');
    const templatePath = fs.existsSync(controllerTemplatePath)
      ? controllerTemplatePath
      : fallbackTemplatePath;
    fs.readFile(templatePath, (error, content) => {
      if (error) {
        console.error(`Unable to read controller template (${templatePath}):`, error);
        response.writeHead(500);
        response.end('Unable to load page');
        return;
      }
      response.writeHead(200, {
        'Cache-Control': 'no-store',
        'Content-Type': 'text/html; charset=utf-8',
      });
      response.end(content);
    });
  });

  const io = new Server(httpServer);
  io.use((socket, next) => {
    const sessionId = getCookie(
      socket.handshake.headers.cookie,
      CONTROLLER_SESSION_COOKIE
    );
    socket.data.controllerSessionId = sessionId;
    next();
  });

  io.on('connection', (socket) => {
    let joinedRoom = null;
    let joinedRole = null;

    socket.on('join', (payload = {}) => {
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        socket.emit('join:error', 'Invalid room, role, or authentication.');
        return;
      }
      if (joinedRoom) {
        socket.emit('join:error', 'This connection has already joined a room.');
        return;
      }
      const { role, token } = payload;
      const authorized = role === 'device'
        ? secureEquals(token, normalizedConfig.deviceToken)
        : role === 'controller' &&
          isControllerSessionValid(controllerSessions, socket.data.controllerSessionId);

      if (!authorized) {
        socket.emit('join:error', 'Invalid room, role, or authentication.');
        return;
      }

      const room = normalizedConfig.sessionCode;
      const roomSockets = io.sockets.adapter.rooms.get(room);
      if (roomSockets && [...roomSockets].some((id) => {
        const peer = io.sockets.sockets.get(id);
        return peer && peer.data.role === role;
      })) {
        socket.emit('join:error', `A ${role} is already connected.`);
        return;
      }

      const peerPresent = roomSockets && [...roomSockets].some((id) => {
        const peer = io.sockets.sockets.get(id);
        return peer && peer.data.role !== role;
      });
      joinedRoom = room;
      joinedRole = role;
      socket.data.role = role;
      socket.join(room);
      socket.emit('join:accepted', {
        peerPresent: Boolean(peerPresent),
        iceServers: createIceServers(normalizedConfig),
      });
      socket.to(room).emit('peer:joined', { role });
    });

    socket.on('signal', (message) => {
      if (!joinedRoom || !['device', 'controller'].includes(joinedRole)) return;
      if (joinedRole === 'controller' &&
          !isControllerSessionValid(controllerSessions, socket.data.controllerSessionId)) {
        socket.emit('join:error', 'Controller session expired.');
        socket.disconnect(true);
        return;
      }
      if (!message || !['offer', 'answer', 'ice'].includes(message.type)) return;
      socket.to(joinedRoom).emit('signal', message);
    });

    socket.on('disconnect', () => {
      if (joinedRoom && joinedRole) {
        socket.to(joinedRoom).emit('peer:left', { role: joinedRole });
      }
    });
  });

  return { httpServer, io, controllerSessions };
}

if (require.main === module) {
  let config;
  try {
    config = loadConfig();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
  if (config) {
    const { httpServer } = createServer(config);
    httpServer.listen(config.port, () => {
      console.log(`AmeriKIDS remote control server listening on port ${httpServer.address().port}`);
    });
  }
}

module.exports = { createIceServers, createServer, loadConfig };
