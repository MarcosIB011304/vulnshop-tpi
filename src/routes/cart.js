// Carrito simple guardado en la sesion. No es el foco de seguridad del TPI,
// pero completa el flujo de compra para que la demo sea realista.
const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { requireLogin } = require('../middleware/auth');

function getCart(req) {
  if (!req.session.cart) req.session.cart = [];
  return req.session.cart;
}

router.post('/cart/add/:id', (req, res) => {
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (product) {
    const cart = getCart(req);
    let qty = parseInt(req.body.qty, 10);
    if (isNaN(qty) || qty < 1) qty = 1;
    if (qty > 20) qty = 20;
    const found = cart.find((i) => i.id === product.id);
    if (found) found.qty += qty;
    else cart.push({ id: product.id, name: product.name, price: product.price, emoji: product.emoji, qty });
  }
  res.redirect('/cart');
});

router.get('/cart', (req, res) => {
  const cart = getCart(req);
  const total = cart.reduce((s, i) => s + i.price * i.qty, 0);
  res.render('cart', { cart, total });
});

router.post('/cart/checkout', requireLogin, (req, res) => {
  const cart = getCart(req);
  if (cart.length === 0) return res.redirect('/cart');
  const total = cart.reduce((s, i) => s + i.price * i.qty, 0);
  const items = JSON.stringify(cart.map((i) => ({ name: i.name, qty: i.qty, price: i.price })));
  const info = db.prepare('INSERT INTO orders (user_id,created_at,total,status,items) VALUES (?,?,?,?,?)')
    .run(res.locals.user.id, new Date().toISOString().slice(0, 10), total, 'En preparacion', items);
  req.session.cart = [];
  res.redirect('/orders/' + info.lastInsertRowid);
});

module.exports = router;
