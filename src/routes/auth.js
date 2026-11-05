// Login / logout. Aqui viven dos problemas: SQL Injection en el login y, en la
// version vulnerable, ausencia de limite de intentos (fuerza bruta).
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { db } = require('../db');
const { SECURE } = require('../config');

// Verifica la contrasena segun como se haya guardado (texto plano o scrypt).
function passwordMatches(stored, plain) {
  if (stored && stored.startsWith('scrypt$')) {
    const [, salt, dk] = stored.split('$');
    const calc = crypto.scryptSync(plain, salt, 32).toString('hex');
    const a = Buffer.from(calc);
    const b = Buffer.from(dk);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  return stored === plain;
}

// En la version segura limitamos los intentos por IP para frenar la fuerza bruta.
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Demasiados intentos de inicio de sesion. Espera unos minutos.',
});

router.get('/login', (req, res) => {
  res.render('login', { error: null, email: '' });
});

function handleLogin(req, res) {
  const { email, password } = req.body;

  if (SECURE) {
    // VERSION SEGURA: consulta parametrizada; nunca se concatena la entrada.
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user || !passwordMatches(user.password, password)) {
      return res.status(401).render('login', { error: 'Credenciales invalidas.', email });
    }
    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    return res.redirect('/');
  }

  // VERSION VULNERABLE: la query se arma concatenando. Con
  //   email:  ' OR '1'='1' --
  // la condicion siempre es verdadera y se entra como el primer usuario (admin),
  // sin saber la contrasena.
  const sql = "SELECT * FROM users WHERE email = '" + email + "' AND password = '" + password + "'";
  let user;
  try {
    user = db.prepare(sql).get();
  } catch (e) {
    return res.status(500).render('login', { error: 'Error SQL: ' + e.message, email });
  }
  if (!user) {
    return res.status(401).render('login', { error: 'Credenciales invalidas.', email });
  }
  req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
  res.redirect('/');
}

// La version segura pasa primero por el limitador de intentos.
router.post('/login', SECURE ? loginLimiter : (req, res, next) => next(), handleLogin);

router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

module.exports = router;
