// Carga datos de ejemplo. Se ejecuta en cada arranque para que la demo siempre
// parta del mismo estado. Las contrasenas se guardan en texto plano a proposito
// en la version vulnerable (ver informe); la version segura las hashea.
const { db, init } = require('./db');
const { SECURE } = require('./config');
const crypto = require('crypto');

// Hash simple para la version segura (en produccion real se usaria bcrypt/scrypt
// con sal por usuario; scrypt viene en el core de Node y alcanza para la demo).
function hash(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const dk = crypto.scryptSync(pw, salt, 32).toString('hex');
  return `scrypt$${salt}$${dk}`;
}

function storePassword(pw) {
  return SECURE ? hash(pw) : pw; // vulnerable: texto plano
}

function seed() {
  init();
  db.exec('DELETE FROM users; DELETE FROM products; DELETE FROM reviews; DELETE FROM orders;');

  const insUser = db.prepare('INSERT INTO users (name,email,password,role,address) VALUES (?,?,?,?,?)');
  insUser.run('Admin', 'admin@vulnshop.test', storePassword('admin123'), 'admin', 'Oficina central');
  insUser.run('Marcos', 'marcos@vulnshop.test', storePassword('marcos123'), 'user', 'Av. Siempreviva 742');
  insUser.run('Lucia', 'lucia@vulnshop.test', storePassword('lucia123'), 'user', 'Calle Falsa 123');

  const insProd = db.prepare('INSERT INTO products (name,category,price,emoji,description) VALUES (?,?,?,?,?)');
  const products = [
    ['Auriculares Bluetooth X200', 'Electronica', 18900, '\u{1F3A7}', 'Auriculares inalambricos con cancelacion de ruido.'],
    ['Teclado mecanico K7', 'Electronica', 24500, '⌨️', 'Teclado mecanico retroiluminado, switches azules.'],
    ['Mouse inalambrico M3', 'Electronica', 7300, '\u{1F5B1}️', 'Mouse ergonomico de 2.4GHz.'],
    ['Mochila Urbana 20L', 'Accesorios', 15000, '\u{1F392}', 'Mochila resistente al agua con puerto USB.'],
    ['Botella termica 750ml', 'Hogar', 6200, '\u{1F9F4}', 'Mantiene la temperatura 12 horas.'],
    ['Lampara LED de escritorio', 'Hogar', 11800, '\u{1F4A1}', 'Lampara con brazo flexible y tres intensidades.'],
    ['Camara web HD', 'Electronica', 13400, '\u{1F4F7}', 'Camara 1080p con microfono integrado.'],
    ['Parlante portatil B2', 'Electronica', 21900, '\u{1F50A}', 'Parlante bluetooth resistente a salpicaduras.'],
  ];
  products.forEach((p) => insProd.run(...p));

  const insRev = db.prepare('INSERT INTO reviews (product_id,author,rating,body) VALUES (?,?,?,?)');
  insRev.run(1, 'lucia_g', 5, 'Excelente calidad, llegaron rapido.');
  insRev.run(1, 'martin88', 4, 'Muy buenos, la bateria dura bastante.');
  insRev.run(2, 'devgamer', 5, 'El mejor teclado que tuve.');

  const insOrder = db.prepare('INSERT INTO orders (user_id,created_at,total,status,items) VALUES (?,?,?,?,?)');
  // Pedido 1 pertenece a Marcos (user_id 2), pedido 2 a Lucia (user_id 3).
  insOrder.run(2, '2026-10-28', 43400, 'En preparacion', JSON.stringify([
    { name: 'Auriculares Bluetooth X200', qty: 1, price: 18900 },
    { name: 'Teclado mecanico K7', qty: 1, price: 24500 },
  ]));
  insOrder.run(3, '2026-10-12', 9900, 'Entregado', JSON.stringify([
    { name: 'Mouse inalambrico M3', qty: 1, price: 7300 },
    { name: 'Botella termica 750ml', qty: 1, price: 6200 },
  ]));

  console.log(`[seed] Datos cargados (MODE=${SECURE ? 'secure' : 'vulnerable'}).`);
}

if (require.main === module) seed();
module.exports = { seed, storePassword };
