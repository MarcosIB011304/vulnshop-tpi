// Configuracion central. La unica diferencia entre la version vulnerable y la
// segura es la variable de entorno MODE. Todo el codigo consulta SECURE para
// decidir que rama ejecutar, de modo que el informe muestra el "antes" y el
// "despues" en el mismo archivo.
const MODE = (process.env.MODE || 'vulnerable').toLowerCase();
const SECURE = MODE === 'secure';

module.exports = {
  MODE,
  SECURE,
  PORT: parseInt(process.env.PORT || '8080', 10),
  // En la version vulnerable el secreto es debil y conocido; en la segura se
  // toma de una variable de entorno con un valor fuerte.
  JWT_SECRET: SECURE ? (process.env.JWT_SECRET || 'c8f2a1e9b7d4306f5a2c9e1b8d7f4a63e0c5b29d1f8a7e34') : 'secret',
  SESSION_SECRET: SECURE ? (process.env.SESSION_SECRET || 'b1d9f3a7c5e208146b9d7f3a1c8e5b20') : 'keyboardcat',
};
