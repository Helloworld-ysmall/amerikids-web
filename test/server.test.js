const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { afterEach, test } = require('node:test');
const { io: createSocketClient } = require('socket.io-client');
const { createIceServers, createServer, loadConfig } = require('../server');

const testConfig = {
  sessionCode: 'test-room',
  deviceToken: 'test-device-token',
  controllerToken: 'test-controller-token',
  stunUrls: ['stun:stun.example.test:3478'],
  turnUrls: ['turn:turn.example.test:3478?transport=udp'],
  turnSharedSecret: 'test-turn-shared-secret',
  turnCredentialTtlSeconds: 900,
  production: false,
  port: 0,
};

const runningServers = [];

async function startServer(overrides = {}) {
  const application = createServer({ ...testConfig, ...overrides });
  await new Promise((resolve) => application.httpServer.listen(0, '127.0.0.1', resolve));
  const address = application.httpServer.address();
  const running = {
    ...application,
    url: `http://127.0.0.1:${address.port}`,
  };
  runningServers.push(running);
  return running;
}

async function stopServer(application) {
  await new Promise((resolve) => application.io.close(resolve));
}

function waitForEvent(socket, event) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${event}`)), 3000);
    socket.once(event, (value) => {
      clearTimeout(timer);
      resolve(value);
    });
  });
}

async function connectSocket(url, cookie) {
  const socket = createSocketClient(url, {
    autoConnect: false,
    transports: ['websocket'],
    extraHeaders: cookie ? { Cookie: cookie } : {},
  });
  const connected = new Promise((resolve, reject) => {
    socket.once('connect', resolve);
    socket.once('connect_error', reject);
  });
  socket.connect();
  await connected;
  return socket;
}

afterEach(async () => {
  while (runningServers.length > 0) {
    await stopServer(runningServers.pop());
  }
});

test('requires deployment secrets and TURN configuration in production', () => {
  assert.throws(() => loadConfig({}), /NODE_ENV must be set/);
  assert.throws(() => loadConfig({ NODE_ENV: 'test' }), /Missing required environment variable/);
  assert.throws(() => loadConfig({
    NODE_ENV: 'production',
    SESSION_CODE: 'room',
    DEVICE_TOKEN: 'd'.repeat(32),
    CONTROLLER_TOKEN: 'c'.repeat(32),
  }), /Production requires TURN_URLS and TURN_SHARED_SECRET/);
  assert.throws(() => loadConfig({
    NODE_ENV: 'production',
    SESSION_CODE: 'room',
    DEVICE_TOKEN: 'device',
    CONTROLLER_TOKEN: 'controller',
    TURN_URLS: 'turn:turn.example.test:3478',
    TURN_SHARED_SECRET: 'test-turn-shared-secret',
  }), /Production secrets must be at least 32 characters/);
});

test('loads a fully configured production environment without embedding defaults', () => {
  const config = loadConfig({
    NODE_ENV: 'production',
    SESSION_CODE: 'server-side-room',
    DEVICE_TOKEN: 'd'.repeat(32),
    CONTROLLER_TOKEN: 'c'.repeat(32),
    TURN_URLS: 'turn:turn.example.test:3478',
    TURN_SHARED_SECRET: 's'.repeat(32),
  });
  assert.equal(config.production, true);
  assert.equal(config.turnUrls[0], 'turn:turn.example.test:3478');
  assert.equal(config.turnCredentialTtlSeconds, 3600);
});

test('issues temporary TURN credentials with the configured STUN servers', () => {
  const [stun, turn] = createIceServers(testConfig);
  assert.deepEqual(stun, { urls: testConfig.stunUrls[0] });
  assert.equal(turn.urls[0], testConfig.turnUrls[0]);
  assert.match(turn.username, /^\d+:amerikids$/);
  const expiresAt = Number(turn.username.split(':', 1)[0]);
  const now = Math.floor(Date.now() / 1000);
  assert.ok(expiresAt > now);
  assert.ok(expiresAt <= now + testConfig.turnCredentialTtlSeconds + 1);
  assert.equal(turn.credential, crypto
    .createHmac('sha1', testConfig.turnSharedSecret)
    .update(turn.username)
    .digest('base64'));
  assert.equal(turn.credentialType, 'password');
});

test('accepts string-based URL collections and defaults missing server config gracefully', () => {
  const custom = createIceServers({
    stunUrls: 'stun:stun.example.test:3478',
    turnUrls: 'turn:turn.example.test:3478',
    turnSharedSecret: 'test-turn-shared-secret',
    turnCredentialTtlSeconds: 900,
  });
  assert.deepEqual(custom[0], { urls: 'stun:stun.example.test:3478' });
  assert.equal(custom[1].urls[0], 'turn:turn.example.test:3478');

  const application = createServer({
    sessionCode: 'fallback-room',
    deviceToken: 'device-token',
    controllerToken: 'controller-token',
    stunUrls: 'stun:stun.example.test:3478',
    turnUrls: 'turn:turn.example.test:3478',
    turnSharedSecret: 'test-turn-shared-secret',
    turnCredentialTtlSeconds: 900,
  });
  assert.ok(application.httpServer);
  assert.ok(application.io);
  assert.equal(application.httpServer instanceof Object, true);
});

test('requires controller authentication and sets secure production cookies', async () => {
  const application = await startServer({ production: true });
  const origin = application.url;
  const health = await fetch(`${origin}/health`);
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: 'ok' });

  const unauthorized = await fetch(`${origin}/session`);
  assert.equal(unauthorized.status, 401);

  const rejectedLogin = await fetch(`${origin}/session/login`, {
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: 'wrong-token' }),
  });
  assert.equal(rejectedLogin.status, 401);
  const crossOriginLogin = await fetch(`${origin}/session/login`, {
    method: 'POST',
    headers: { Origin: 'https://other.example.test', 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: testConfig.controllerToken }),
  });
  assert.equal(crossOriginLogin.status, 403);

  const login = await fetch(`${origin}/session/login`, {
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: testConfig.controllerToken }),
  });
  assert.equal(login.status, 204);
  const setCookie = login.headers.get('set-cookie');
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Strict/);
  assert.match(setCookie, /Secure/);

  const cookie = setCookie.split(';', 1)[0];
  const authorized = await fetch(`${origin}/session`, { headers: { Cookie: cookie } });
  assert.equal(authorized.status, 204);
});

test('authenticates device and controller joins and relays WebRTC signaling', async () => {
  const application = await startServer();

  const login = await fetch(`${application.url}/session/login`, {
    method: 'POST',
    headers: { Origin: application.url, 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: testConfig.controllerToken }),
  });
  assert.equal(login.status, 204);
  const cookie = login.headers.get('set-cookie').split(';', 1)[0];

  const unauthenticatedController = await connectSocket(application.url);
  const rejectedController = waitForEvent(unauthenticatedController, 'join:error');
  unauthenticatedController.emit('join', { role: 'controller' });
  assert.match(await rejectedController, /authentication/);
  unauthenticatedController.disconnect();

  const rejectedDevice = await connectSocket(application.url);
  const rejected = waitForEvent(rejectedDevice, 'join:error');
  rejectedDevice.emit('join', { role: 'device', token: 'wrong-token' });
  assert.match(await rejected, /authentication/);
  rejectedDevice.disconnect();

  const device = await connectSocket(application.url);
  const deviceAccepted = waitForEvent(device, 'join:accepted');
  device.emit('join', { role: 'device', token: testConfig.deviceToken });
  assert.equal((await deviceAccepted).peerPresent, false);

  const controller = await connectSocket(application.url, cookie);
  const deviceJoined = waitForEvent(device, 'peer:joined');
  const controllerAccepted = waitForEvent(controller, 'join:accepted');
  controller.emit('join', { role: 'controller' });
  const joinResult = await controllerAccepted;
  assert.equal(joinResult.peerPresent, true);
  assert.equal(Object.hasOwn(joinResult, 'sessionCode'), false);
  assert.equal(joinResult.iceServers.length, 2);
  assert.equal(joinResult.iceServers[1].credentialType, 'password');
  assert.deepEqual(await deviceJoined, { role: 'controller' });

  const offer = { type: 'offer', sdp: 'test-sdp' };
  const receivedOffer = waitForEvent(device, 'signal');
  controller.emit('signal', offer);
  assert.deepEqual(await receivedOffer, offer);

  device.disconnect();
  controller.disconnect();
});
