const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Server } = require('socket.io');

const SESSION_CODE = process.env.SESSION_CODE;
const DEVICE_TOKEN = process.env.DEVICE_TOKEN;
const CONTROLLER_TOKEN = process.env.CONTROLLER_TOKEN;
const CONTROLLER_SESSION_COOKIE = 'amerikids_controller_session';
const CONTROLLER_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const controllerSessions = new Map();

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

function isControllerSessionValid(sessionId) {
  const expiresAt = sessionId && controllerSessions.get(sessionId);
  if (!expiresAt) return false;
  if (expiresAt <= Date.now()) {
    controllerSessions.delete(sessionId);
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

async function handleControllerLogin(request, response) {
  const origin = request.headers.origin;
  const requestHost = (request.headers['x-forwarded-host'] || request.headers.host || '')
    .split(',')[0]
    .trim();
  if (origin) {
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

  if (!credentials || credentials.token !== CONTROLLER_TOKEN) {
    sendJson(response, 401, { error: 'Invalid controller token.' });
    return;
  }

  const sessionId = crypto.randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + CONTROLLER_SESSION_TTL_MS;
  for (const [existingId, existingExpiry] of controllerSessions) {
    if (existingExpiry <= Date.now()) controllerSessions.delete(existingId);
  }
  controllerSessions.set(sessionId, expiresAt);
  response.writeHead(204, {
    'Cache-Control': 'no-store',
    'Set-Cookie': `${CONTROLLER_SESSION_COOKIE}=${sessionId}; Max-Age=${CONTROLLER_SESSION_TTL_MS / 1000}; Path=/; HttpOnly; Secure; SameSite=Strict`,
  });
  response.end();
}

const missingVariables = [
  ['SESSION_CODE', SESSION_CODE],
  ['DEVICE_TOKEN', DEVICE_TOKEN],
  ['CONTROLLER_TOKEN', CONTROLLER_TOKEN],
].filter(([, value]) => !value)
  .map(([name]) => name);

if (missingVariables.length > 0) {
  console.error(`Missing required environment variable(s): ${missingVariables.join(', ')}`);
  process.exitCode = 1;
} else {
  const server = http.createServer((request, response) => {
    const requestUrl = new URL(request.url, 'http://localhost');

    if (request.method === 'GET' && requestUrl.pathname === '/') {
      response.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      response.end('AmeriKIDS WebRTC Signaling Server is Running!');
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/session/login') {
      handleControllerLogin(request, response).catch((error) => {
        console.error('Controller sign-in failed:', error);
        if (!response.headersSent) {
          sendJson(response, 500, { error: 'Unable to sign in.' });
        } else {
          response.destroy(error);
        }
      });
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname === '/session') {
      const sessionId = getCookie(
        request.headers.cookie,
        CONTROLLER_SESSION_COOKIE
      );
      if (isControllerSessionValid(sessionId)) {
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

    fs.readFile(path.join(__dirname, 'index.html'), (error, content) => {
      if (error) {
        console.error('Unable to read index.html:', error);
        response.writeHead(500);
        response.end('Unable to load page');
        return;
      }

      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      response.end(content);
    });
  });

  const io = new Server(server);

  io.use((socket, next) => {
    const sessionId = getCookie(
      socket.handshake.headers.cookie,
      CONTROLLER_SESSION_COOKIE
    );
    socket.data.controllerAuthenticated = isControllerSessionValid(sessionId);
    next();
  });

  io.on('connection', (socket) => {
    let joinedRoom = null;
    let joinedRole = null;

    socket.on('join', ({ room, role, token } = {}) => {
      if (joinedRoom) {
        socket.emit('join:error', 'This connection has already joined a room.');
        return;
      }

      const authorized = role === 'device'
        ? token === DEVICE_TOKEN
        : role === 'controller' && socket.data.controllerAuthenticated;

      const targetRoom = role === 'controller' && socket.data.controllerAuthenticated
        ? SESSION_CODE
        : room;
      if (targetRoom !== SESSION_CODE || !authorized) {
        socket.emit('join:error', 'Invalid room, role, or token.');
        return;
      }

      const roomSockets = io.sockets.adapter.rooms.get(targetRoom);
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
      joinedRoom = targetRoom;
      joinedRole = role;
      socket.data.role = role;
      socket.join(targetRoom);
      socket.emit('join:accepted', { peerPresent: Boolean(peerPresent) });
      socket.to(targetRoom).emit('peer:joined', { role });
    });

    socket.on('signal', (message) => {
      if (!joinedRoom || !['device', 'controller'].includes(joinedRole)) return;
      if (!message || !['offer', 'answer', 'ice'].includes(message.type)) return;
      socket.to(joinedRoom).emit('signal', message);
    });

    socket.on('disconnect', () => {
      if (joinedRoom && joinedRole) {
        socket.to(joinedRoom).emit('peer:left', { role: joinedRole });
      }
    });
  });

  server.listen(process.env.PORT || 3000, () => {
    console.log(`AmeriKIDS remote control server listening on port ${server.address().port}`);
  });
}
