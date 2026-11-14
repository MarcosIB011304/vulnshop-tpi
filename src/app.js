const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');

const { SECURE, MODE, PORT, SESSION_SECRET } = require('./config');
const { seed } = require('./seed');
const { currentUser } = require('./middleware/auth');
const csrf = require('./lib/csrf');

const app = express();

// Vistas
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Archivos estaticos (imagenes de producto, iconos). Mismo origen, asi cargan
// sin depender de internet y pasan la CSP del modo seguro (default-src 'self').
app.use('/static', express.static(path.join(__dirname, 'public')));

// Cookie de sesion. En la version segura se marca HttpOnly + SameSite=strict,
// lo que corta el robo por XSS y buena parte del CSRF. En la vulnerable se deja
// accesible desde JavaScript (httpOnly:false) y sin SameSite.
app.use(session({
  name: 'sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: SECURE,
    sameSite: SECURE ? 'strict' : false,
  },
}));

// Cabeceras de seguridad. CSP solo en la version segura: bloquea la ejecucion
// de scripts inline inyectados por XSS.
app.use((req, res, next) => {
  if (SECURE) {
    res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
  }
  next();
});

// Variables disponibles en todas las vistas.
app.use((req, res, next) => {
  res.locals.user = currentUser(req);
  res.locals.SECURE = SECURE;
  res.locals.MODE = MODE;
  res.locals.csrfToken = SECURE ? csrf.getToken(req) : '';
  next();
});

// Rutas
app.use('/', require('./routes/index'));
app.use('/', require('./routes/auth'));
app.use('/', require('./routes/product'));
app.use('/', require('./routes/cart'));
app.use('/', require('./routes/profile'));
app.use('/', require('./routes/orders'));
app.use('/api', require('./routes/api'));

app.use((req, res) => res.status(404).render('page', {
  title: 'No encontrado', body: '<h1>404</h1><p>Pagina no encontrada.</p>',
}));

seed();
app.listen(PORT, () => {
  console.log('================================================');
  console.log(`  VulnShop corriendo en modo: ${MODE.toUpperCase()}`);
  console.log(`  http://localhost:${PORT}`);
  console.log('================================================');
});
