// Detalle de producto y reseñas. Aqui vive el XSS almacenado: una reseña se
// guarda tal cual la escribe el usuario y se vuelve a mostrar a todos.
const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { SECURE } = require('../config');

router.get('/product/:id', (req, res) => {
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!product) return res.status(404).render('page', { title: 'No encontrado', body: '<p>Producto inexistente.</p>' });
  const reviews = db.prepare('SELECT * FROM reviews WHERE product_id = ? ORDER BY id DESC').all(product.id);
  res.render('product', { product, reviews });
});

router.post('/product/:id/review', (req, res) => {
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!product) return res.status(404).send('Producto inexistente.');
  const author = (res.locals.user && res.locals.user.name) || 'anonimo';
  const rating = parseInt(req.body.rating || '5', 10);
  const body = req.body.body || '';

  // En ambos casos se guarda el texto crudo (el XSS almacenado se mitiga al
  // MOSTRAR, no al guardar). La diferencia aparece en la vista product.ejs:
  //  - vulnerable: <%- r.body %>  (sin escapar -> el <script> se ejecuta)
  //  - segura:     <%= r.body %>  (escapado) + cabecera CSP + cookie HttpOnly
  db.prepare('INSERT INTO reviews (product_id,author,rating,body) VALUES (?,?,?,?)')
    .run(product.id, author, isNaN(rating) ? 5 : rating, body);

  res.redirect('/product/' + product.id);
});

module.exports = router;
