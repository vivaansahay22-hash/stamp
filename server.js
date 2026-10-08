const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const ROOT = __dirname;

function sendJson(response, status, payload) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  response.end(JSON.stringify(payload));
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.on('data', (chunk) => {
      body += chunk;
      if (body.length > 10_000) request.destroy();
    });
    request.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(new Error('Invalid JSON'));
      }
    });
    request.on('error', reject);
  });
}

const server = http.createServer(async (request, response) => {
  const requestUrl = new URL(request.url, `http://${request.headers.host}`);

  if (request.method === 'GET' && requestUrl.pathname === '/api/health') {
    sendJson(response, 200, { ok: true });
    return;
  }

  if (request.method === 'POST' && requestUrl.pathname === '/api/plan') {
    try {
      const body = await readBody(request);
      const tasks = Array.isArray(body.tasks) ? body.tasks : [];
      const alarms = Array.isArray(body.alarms) ? body.alarms : [];
      const rigidTasks = tasks.filter((task) => String(task.type || '').toLowerCase() === 'rigid');
      const flexibleTasks = tasks.filter((task) => String(task.type || '').toLowerCase() === 'flexible');

      const summary = rigidTasks.length
        ? `Keep ${rigidTasks[0].title} as your anchor and protect its time first. Then use ${flexibleTasks[0]?.title || 'flexible blocks'} to absorb the rest of the day.`
        : 'No rigid blocks yet. Add your must-do commitments first and let the flexible blocks fill around them.';

      sendJson(response, 200, {
        ok: true,
        summary,
        rigidCount: rigidTasks.length,
        flexibleCount: flexibleTasks.length,
        alarmCount: alarms.length
      });
    } catch (error) {
      sendJson(response, 400, { error: error.message });
    }
    return;
  }

  if (request.method === 'GET') {
    const requestedPath = requestUrl.pathname === '/' ? '/index.html' : requestUrl.pathname;
    const filePath = path.resolve(ROOT, `.${requestedPath}`);
    if (!filePath.startsWith(ROOT)) {
      sendJson(response, 403, { error: 'Forbidden' });
      return;
    }

    fs.readFile(filePath, (error, file) => {
      if (error) {
        response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        response.end('Not found');
        return;
      }
      const contentType = filePath.endsWith('.html') ? 'text/html; charset=utf-8' : 'text/plain; charset=utf-8';
      response.writeHead(200, { 'Content-Type': contentType });
      response.end(file);
    });
    return;
  }

  sendJson(response, 405, { error: 'Method not allowed' });
});

server.listen(PORT, HOST, () => {
  console.log(`Stillpoint is running at http://${HOST}:${PORT}`);
});
