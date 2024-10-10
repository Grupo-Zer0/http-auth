const express = require('express');
const { getUser } = require('./database');
const crypto = require('crypto');
const app = express();
const exec = require('child_process').exec;
const realm = 'User Visible Realm';

app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware para autenticar usando Auth Basic HTTP
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    // Si no hay cabecera de autorización o no es del tipo Basic, pedir credenciales
    res.setHeader('WWW-Authenticate', `Basic realm="${realm}"`);
    return res.status(401).send('Autenticación requerida');
  }

  // Decodificar credenciales base64
  const base64Credentials = authHeader.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
  const [username, password] = credentials.split(':');

  const user = getUser(username);
  const md5hash = crypto.createHash('md5').update(password).digest('hex');

  if (!user || user.password !== md5hash) {
    // Si el usuario no existe o la contraseña es incorrecta
    res.setHeader('WWW-Authenticate', `Basic realm="${realm}"`);
    return res.status(401).send('Credenciales incorrectas');
  }

  // Si las credenciales son correctas, continuar con la siguiente función
  return next();
}

// Rutas protegidas por la autenticación Basic
app.get('/protected', authMiddleware, (req, res) => {
  const authHeader = req.headers['authorization'];
  const base64Credentials = authHeader.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
  const [username] = credentials.split(':');
  
  res.send(`Bienvenido ${username}, has accedido a una ruta protegida.`);
});

app.get('/logout', (req, res) => {
  //res.setHeader('WWW-Authenticate', `Basic realm="${realm}"`);
  res.status(401).send('Has sido deslogueado');
});


app.get('/trace', (req, res) => {
  //text comes from http form
  var text = req.query.text;
  //execute the command
  
  exec(`traceroute ${text}`, (error, stdout, stderr) => {
    if (error) {
      res.send(`error: ${error.message}`);
      return;
    }
    if (stderr) {
      res.send(`stderr: ${stderr}`);
      return;
    }
    res.send(`stdout: ${stdout}`);
  });
});

// Ruta sin protección para pruebas
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Iniciar el servidor
app.listen(3000, () => {
  console.log('Servidor escuchando en http://localhost:3000');
});
