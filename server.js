const http = require('http');
const fs = require('fs');
const path = require('path');
const { Server } = require('socket.io');

const SESSION_CODE = process.env.SESSION_CODE;
const DEVICE_TOKEN = process.env.DEVICE_TOKEN;
const CONTROLLER_TOKEN = process.env.CONTROLLER_TOKEN;

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

    if (request.method !== 'GET') {
      response.writeHead(405, { Allow: 'GET' });
      response.end('Method Not Allowed');
      return;
    }

    if (requestUrl.pathname !== '/') {
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

  io.on('connection', (socket) => {
    let joinedRoom = null;
    let joinedRole = null;

    socket.on('join', ({ room, role, token } = {}) => {
      if (joinedRoom) {
        socket.emit('join:error', 'This connection has already joined a room.');
        return;
      }

      const expectedToken = role === 'device'
        ? DEVICE_TOKEN
        : role === 'controller'
          ? CONTROLLER_TOKEN
          : null;

      if (room !== SESSION_CODE || !expectedToken || token !== expectedToken) {
        socket.emit('join:error', 'Invalid room, role, or token.');
        return;
      }

      joinedRoom = room;
      joinedRole = role;
      socket.join(room);
      socket.emit('join:accepted');
    });

    socket.on('frame', (frame) => {
      if (joinedRoom && joinedRole === 'device') {
        socket.to(joinedRoom).emit('frame', frame);
      }
    });

    socket.on('command', (command) => {
      if (joinedRoom && joinedRole === 'controller') {
        socket.to(joinedRoom).emit('command', command);
      }
    });
  });

  server.listen(process.env.PORT || 3000, () => {
    console.log(`AmeriKIDS remote control server listening on port ${server.address().port}`);
  });
}
