// Perfil del usuario. Aqui vive el CSRF: el formulario de cambio de email no
// lleva token anti-CSRF en la version vulnerable, asi que una pagina externa
// puede forzar el cambio sobre la victima logueada.
const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { SECURE } = require('../config');
const { requireLogin } = require('../middleware/auth');
const { verifyCsrf } = require('../lib/csrf');
const jwt = require('../lib/jwt');

router.get('/profile', requireLogin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(res.locals.user.id);
  // Token JWT que usa la API (ver routes/api.js). Se muestra para la demo de JWT.
  const apiToken = jwt.sign({ uid: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + 3600 });
  res.render('profile', { profile: user, apiToken });
});

// La version segura intercala la verificacion del token anti-CSRF.
const csrfGuard = SECURE ? verifyCsrf : (req, res, next) => next();

router.post('/profile/email', requireLogin, csrfGuard, (req, res) => {
  const newEmail = req.body.email;
  if (newEmail) {
    db.prepare('UPDATE users SET email = ? WHERE id = ?').run(newEmail, res.locals.user.id);
    req.session.user.email = newEmail;
  }
  res.redirect('/profile');
});

module.exports = router;
