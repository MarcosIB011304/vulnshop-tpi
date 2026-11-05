// Helpers de sesion web. El login guarda el usuario en req.session.
function currentUser(req) {
  return req.session && req.session.user ? req.session.user : null;
}

function requireLogin(req, res, next) {
  if (!currentUser(req)) return res.redirect('/login');
  next();
}

module.exports = { currentUser, requireLogin };
