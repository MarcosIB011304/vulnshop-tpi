// Listado y detalle de pedidos. Aqui vive el IDOR: el detalle se obtiene por id
// sin verificar que el pedido pertenezca al usuario logueado.
const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { SECURE } = require('../config');
const { requireLogin } = require('../middleware/auth');

router.get('/orders', requireLogin, (req, res) => {
  const orders = db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC').all(res.locals.user.id);
  res.render('orders', { orders });
});

router.get('/orders/:id', requireLogin, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).render('page', { title: 'No encontrado', body: '<p>Pedido inexistente.</p>' });

  if (SECURE) {
    // VERSION SEGURA: se controla que el recurso sea del usuario (o que sea
    // admin). Si no, se responde 403 y no se filtra nada.
    if (order.user_id !== res.locals.user.id && res.locals.user.role !== 'admin') {
      return res.status(403).render('page', { title: 'Prohibido', body: '<h1>403</h1><p>No tenes permiso para ver este pedido.</p>' });
    }
  }
  // VERSION VULNERABLE: no hay control de propietario. Cambiando el numero en la
  // URL (/orders/2) se ven pedidos de otros usuarios.

  const owner = db.prepare('SELECT name,email FROM users WHERE id = ?').get(order.user_id);
  res.render('order_detail', { order, items: JSON.parse(order.items), owner });
});

module.exports = router;
