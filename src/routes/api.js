// API autenticada por JWT. Demuestra la validacion debil de tokens.
// GET  /api/me           -> datos del usuario del token
// GET  /api/admin/users  -> solo si role == admin (se puede falsificar en la
//                           version vulnerable con alg:none o secreto debil)
const express = require('express');
const router = express.Router();
const { db } = require('../db');
const jwt = require('../lib/jwt');

function auth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = jwt.verify(token);
  if (!payload) return res.status(401).json({ error: 'Token invalido o ausente' });
  req.auth = payload;
  next();
}

router.get('/me', auth, (req, res) => {
  res.json({ uid: req.auth.uid, role: req.auth.role });
});

router.get('/admin/users', auth, (req, res) => {
  if (req.auth.role !== 'admin') {
    return res.status(403).json({ error: 'Se requiere rol admin' });
  }
  const users = db.prepare('SELECT id,name,email,role FROM users').all();
  res.json({ users });
});

module.exports = router;
