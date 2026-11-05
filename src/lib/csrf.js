// Token anti-CSRF por sesion. Solo se aplica en la version segura.
const crypto = require('crypto');

function getToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  }
  return req.session.csrfToken;
}

// Middleware que valida el token en peticiones que cambian estado (POST).
function verifyCsrf(req, res, next) {
  const sent = req.body._csrf;
  if (!sent || sent !== req.session.csrfToken) {
    return res.status(403).send('CSRF token invalido o ausente.');
  }
  next();
}

module.exports = { getToken, verifyCsrf };
