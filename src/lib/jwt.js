// Implementacion minima de JWT (HS256) para demostrar la vulnerabilidad de
// validacion. NO usar en produccion: aca el objetivo es mostrar el "antes" y el
// "despues". En un proyecto real se usa la libreria jsonwebtoken.
const crypto = require('crypto');
const { SECURE, JWT_SECRET } = require('../config');

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString();
}

function sign(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64url(sig)}`;
}

// Devuelve el payload si el token es valido, o null si no lo es.
function verify(token) {
  if (!token || token.split('.').length !== 3) return null;
  const [h, p, s] = token.split('.');
  let header, payload;
  try {
    header = JSON.parse(b64urlDecode(h));
    payload = JSON.parse(b64urlDecode(p));
  } catch (e) {
    return null;
  }

  if (SECURE) {
    // VERSION SEGURA: se exige HS256 (se rechaza alg:none y cualquier otro),
    // se recalcula la firma con el secreto fuerte y se compara de forma
    // segura, y se verifica la expiracion.
    if (header.alg !== 'HS256') return null;
    const expected = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest());
    const a = Buffer.from(s);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  }

  // VERSION VULNERABLE: confia en el header del atacante.
  //  - Si alg == 'none', acepta el token sin firma.
  //  - Si no, verifica con un secreto debil ('secret'), facil de adivinar.
  // Ademas no controla expiracion.
  if (header.alg === 'none') return payload;
  const expected = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest());
  if (s === expected) return payload;
  return null;
}

module.exports = { sign, verify, b64url };
