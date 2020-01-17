import * as Debug from 'debug';
import * as http from 'http';
import { app } from './app';

const debug = Debug('sr-auth:server');

const port = normalizePort(process.env.SVC_PORT || '3000');
app.set('port', port);

const server = http.createServer(app);
server.listen(port);

server.on('error', (error: any) => {
  if (error.syscall !== 'listen') {
    throw error;
  }
  const bind = typeof port === 'string' ? 'Pipe ' + port : 'Port ' + port;
  switch (error.code) {
    case 'EACCES':
      console.error(bind + ' requires elevated privileges');
      process.exit(1);
      break;
    case 'EADDRINUSE':
      console.error(bind + ' is already in use');
      process.exit(1);
      break;
    default:
      throw error;
  }
});

server.on('listening', () => {
  debug('Listening on ' + server.address());
});

function normalizePort(val: string) {
  const port = parseInt(val, 10);
  if (isNaN(port)) {
    return val;
  }
  if (port >= 0) {
    return port;
  }
  return false;
}
