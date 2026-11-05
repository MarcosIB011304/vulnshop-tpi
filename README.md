# VulnShop — Tienda vulnerable y su versión segura

Trabajo Práctico Integrador — **Seguridad en el Desarrollo de Software** (UTN, Ingeniería en Sistemas de Información).

VulnShop es una tienda online chica (catálogo, login, carrito, perfil, reseñas y pedidos) construida con **el mismo código** en dos versiones: una **vulnerable** y una **segura**. La versión se elige con la variable de entorno `MODE`, de modo que el código vulnerable y el corregido quedan uno al lado del otro en cada archivo (buscá los comentarios `VERSION VULNERABLE` / `VERSION SEGURA`).

## Integrantes

- Daniel Alexander Patolsky
- Angel Nahuel Luna (89627)
- Marcos Ignacio Belli (95348)
- Marcos Mitnik (89499)
- Valentino Gabriel Rocca (94774)

## Vulnerabilidades incluidas

| # | Vulnerabilidad | Dónde | OWASP Top 10 (2021) |
|---|----------------|-------|---------------------|
| 1 | SQL Injection | Login y buscador | A03: Injection |
| 2 | XSS almacenado | Reseñas de productos | A03: Injection |
| 3 | IDOR | Detalle de pedido `/orders/:id` | A01: Broken Access Control |
| 4 | JWT mal validado | API `/api/*` | A02 / A07 |
| 5 | CSRF | Cambio de email del perfil | A01: Broken Access Control |
| extra | Fuerza bruta | Login sin rate limiting | A07: Auth Failures |

## Cómo levantarla

### Con Docker (recomendado)

```bash
docker compose up --build
```

- Versión **vulnerable**: http://localhost:18080
- Versión **segura**: http://localhost:18081

### Sin Docker (Node 20+)

```bash
npm install
# Vulnerable
MODE=vulnerable PORT=18080 npm start
# Segura (en otra terminal)
MODE=secure PORT=18081 npm start
```

> En Windows (PowerShell): `$env:MODE="vulnerable"; $env:PORT="18080"; npm start`

La base se recrea con datos de ejemplo en cada arranque.

### Usuarios de prueba

| Email | Contraseña | Rol |
|-------|-----------|-----|
| admin@vulnshop.test | admin123 | admin |
| marcos@vulnshop.test | marcos123 | user |
| lucia@vulnshop.test | lucia123 | user |

## Guion de la demo

La idea es mostrar cada ataque en **18080 (vulnerable)** y repetirlo en **18081 (segura)** para ver que falla.

1. **SQL Injection (login).** En la pantalla de login de la vulnerable, email: `' OR '1'='1' -- ` y cualquier contraseña → entrás como admin. En la segura devuelve "Credenciales inválidas".
2. **SQL Injection (buscador + sqlmap).** En el buscador: `' UNION SELECT id,email,password,role,id,email FROM users -- ` → aparecen los usuarios y sus contraseñas. Con sqlmap: `sqlmap -u "http://localhost:18080/?q=test" -p q --batch --dump -T users`.
3. **XSS almacenado.** En un producto, publicá la reseña `<script>alert(document.cookie)</script>`. En la vulnerable se ejecuta al recargar; en la segura se ve el texto escapado y la CSP lo bloquea.
4. **IDOR.** Logueado como Marcos, entrá a `/orders/2` (pedido de Lucía). En la vulnerable lo ves; en la segura da 403.
5. **JWT mal validado.** Pedí `/api/admin/users` con un token `alg:none` forjado con `role:admin` (ver `informe/`). En la vulnerable responde la lista de usuarios; en la segura da 401.
6. **CSRF.** Logueado en la vulnerable, abrí `informe/csrf-poc.html`: te cambia el email sin tu intervención. En la segura el POST sin token anti-CSRF da 403.

## Estructura

```
src/
  app.js            arranque, sesión, cabeceras de seguridad
  config.js         MODE -> SECURE (interruptor central)
  db.js, seed.js    SQLite y datos de ejemplo
  lib/jwt.js        verificación de JWT (débil vs. estricta)
  lib/csrf.js       token anti-CSRF (solo versión segura)
  routes/           una vulnerabilidad por archivo
  views/            plantillas EJS
informe/            tutorial técnico y PoC de CSRF
docker-compose.yml  levanta las dos versiones
```

## Aviso

Este proyecto es **deliberadamente inseguro** y sirve solo para fines educativos en un entorno local y controlado. No lo expongas a Internet.
