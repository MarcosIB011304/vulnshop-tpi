// Catalogo y buscador. Aqui vive la vulnerabilidad de SQL Injection en la
// busqueda de productos.
const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { SECURE } = require('../config');

router.get('/', (req, res) => {
  const q = req.query.q;
  let products;
  let sqlShown = null;

  if (q) {
    if (SECURE) {
      // VERSION SEGURA: consulta parametrizada. El valor del usuario viaja como
      // parametro y nunca se interpreta como SQL.
      const sql = "SELECT * FROM products WHERE name LIKE ? OR category LIKE ?";
      products = db.prepare(sql).all(`%${q}%`, `%${q}%`);
      sqlShown = sql;
    } else {
      // VERSION VULNERABLE: se concatena el texto del usuario dentro de la query.
      // Un valor como:  ' UNION SELECT id,email,password,role,id,email FROM users --
      // permite volcar la tabla users. sqlmap automatiza esto.
      const sql = "SELECT * FROM products WHERE name LIKE '%" + q + "%' OR category LIKE '%" + q + "%'";
      sqlShown = sql;
      try {
        products = db.prepare(sql).all();
      } catch (e) {
        // Mostrar el error de SQL tambien ayuda al atacante (fuga de informacion).
        return res.render('catalog', { products: [], q, sqlShown, error: e.message });
      }
    }
  } else {
    products = db.prepare('SELECT * FROM products').all();
  }

  res.render('catalog', { products, q: q || '', sqlShown, error: null });
});

module.exports = router;
