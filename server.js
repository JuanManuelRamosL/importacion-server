/* const express = require("express");
const { calcularImportacionCourierSimple } = require("./utils/importacion.js");
const db = require("./db");
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para parsear JSON
app.use(express.json());

app.post("/users", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: "name, email y password son requeridos" });
    }

    const password_hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare(`
      INSERT INTO users (name, email, password_hash)
      VALUES (?, ?, ?)
    `);
    const info = stmt.run(name, email.toLowerCase(), password_hash);

    return res.status(201).json({ id: info.lastInsertRowid, name, email: email.toLowerCase() });
  } catch (err) {
    if (String(err).includes("UNIQUE constraint failed: users.email")) {
      return res.status(409).json({ error: "El email ya está registrado" });
    }
    return res.status(500).json({ error: "Error al crear usuario" });
  }
});


// Endpoint para calcular importación
app.post("/calcular-importacion", (req, res) => {
  try {
    const { producto, flete } = req.body;

    // Validar que se enviaron los parámetros requeridos
    if (producto === undefined || flete === undefined) {
      return res.status(400).json({
        error: 'Se requieren los parámetros "producto" y "flete"',
      });
    }

    // Calcular importación
    const resultado = calcularImportacionCourierSimple(producto, flete);

    res.json({
      success: true,
      data: resultado,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});



// Endpoint de prueba
app.get("/health", (req, res) => {
  res.json({ status: "OK", message: "Servidor funcionando correctamente" });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
  console.log(
    `Endpoint disponible: POST http://localhost:${PORT}/calcular-importacion`
  );
});
 */


require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const { Sequelize, DataTypes } = require('sequelize');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);
app.use(express.json());

// ---------- Sequelize (PostgreSQL) ----------
/* const sequelize = new Sequelize(
  'importacion',         // database
  "neondb_owner",//'postgres',            // user
  "npg_xS3TXWR2cmwi",//'juanma123',           // password
  {
    host: "ep-old-unit-ac862egj-pooler.sa-east-1.aws.neon.tech",//'localhost',
    port: 1111,
    dialect: 'postgres',
    logging: false,
    pool: { max: 10, idle: 30000 },
    dialectOptions: {}   // sin SSL para local
  }
); */

const sequelize = new Sequelize(
  'neondb',                 // <- nombre de la DB (viene en la URL de Neon)
  'neondb_owner',           // <- usuario
  'npg_xS3TXWR2cmwi',       // <- password
  {
    host: 'ep-old-unit-ac862egj-pooler.sa-east-1.aws.neon.tech', // host *pooler*
    port: 5432,                 // <- Neon usa 5432
    dialect: 'postgres',
    logging: false,
    pool: { max: 10, idle: 30000 },
    dialectOptions: {
      ssl: { require: true }    // <- SSL obligatorio en Neon
      // Si tu runtime no confía en la CA, agrega:
      // , rejectUnauthorized: true  // (Neon tiene cert válido; normalmente NO hace falta tocar esto)
    }
  }
);

// ---------- Modelos ----------
const User = sequelize.define('User', {
  id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
  name: { type: DataTypes.TEXT, allowNull: false },
  email: { type: DataTypes.TEXT, allowNull: false, unique: true },
  password_hash: { type: DataTypes.TEXT, allowNull: false },
}, {
  tableName: 'users',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: false,
});

const Quote = sequelize.define('Quote', {
  id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
  producto: { type: DataTypes.DECIMAL(12,2), allowNull: false },
  flete: { type: DataTypes.DECIMAL(12,2), allowNull: false },
  seguro: { type: DataTypes.DECIMAL(12,2), allowNull: false },
  cif: { type: DataTypes.DECIMAL(12,2), allowNull: false },
  derechos_importacion: { type: DataTypes.DECIMAL(12,2), allowNull: false },
  tasa_estadistica: { type: DataTypes.DECIMAL(12,2), allowNull: false },
  base_iva: { type: DataTypes.DECIMAL(12,2), allowNull: false },
  iva: { type: DataTypes.DECIMAL(12,2), allowNull: false },
  total_impuestos: { type: DataTypes.DECIMAL(12,2), allowNull: false },
  honorarios_courier: { type: DataTypes.DECIMAL(12,2), allowNull: false },
  total_con_courier: { type: DataTypes.DECIMAL(12,2), allowNull: false },
  costo_final: { type: DataTypes.DECIMAL(12,2), allowNull: false },
}, {
  tableName: 'quotes',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: false,
});

// Relaciones
User.hasMany(Quote, { foreignKey: 'user_id' });
Quote.belongsTo(User, { foreignKey: 'user_id' });

// ---------- Cálculo de importación ----------
const DER_IMPORT_PCT = 0.16;  // 16%
const TASA_ESTAD_PCT = 0.03;  // 3%
const IVA_PCT        = 0.21;  // 21%
const SEGURO_PCT     = 0.01;  // 1%
const HONORARIOS     = 60;    // USD
const r2 = (x) => Math.round((x + Number.EPSILON) * 100) / 100;

function calcularImportacionCourierSimple(producto, flete) {
  const P = Number(producto);
  const F = Number(flete);
  if (!Number.isFinite(P) || !Number.isFinite(F) || P < 0 || F < 0) {
    throw new Error('Producto y flete deben ser números >= 0');
  }
  const seguro = r2((P + F) * SEGURO_PCT);
  const cif = r2(P + F + seguro);
  const derechosImportacion = r2(cif * DER_IMPORT_PCT);
  const tasaEstadistica     = r2(cif * TASA_ESTAD_PCT);
  const baseIVA = r2(cif + derechosImportacion + tasaEstadistica);
  const iva     = r2(baseIVA * IVA_PCT);
  const totalImpuestos  = r2(derechosImportacion + tasaEstadistica + iva);
  const totalConCourier = r2(totalImpuestos + HONORARIOS);
  const costoFinal = r2(P + F + totalConCourier);

  return {
    seguro, cif,
    derechosImportacion,
    tasaEstadistica,
    baseIVA, iva,
    totalImpuestos,
    honorariosCourier: HONORARIOS,
    totalConCourier,
    costoFinal,
  };
}


const jwt = require('jsonwebtoken');

// Config inline (cámbialo por algo largo/aleatorio en prod)
const JWT_SECRET  = 'reemplaza-por-una-clave-bien-larga-y-unica-32+chars';
const JWT_EXPIRES = '7d';

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

function auth(req, res, next) {
  try {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'No autenticado' });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, email, name }
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}


// ---------- Rutas ----------
app.post('/users', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name, email y password son requeridos' });
    }
    const password_hash = await bcrypt.hash(password, 10);
    const user = await User.create({
      name,
      email: email.toLowerCase(),
      password_hash,
    });
    res.status(201).json({ id: user.id, name: user.name, email: user.email });
  } catch (err) {
    if (String(err).includes('unique')) {
      return res.status(409).json({ error: 'El email ya está registrado' });
    }
    res.status(500).json({ error: 'Error al crear usuario' });
  }
});

app.post('/calcular-importacion', async (req, res) => {
  try {
    const { producto, flete, userId } = req.body || {};
    if (producto === undefined || flete === undefined) {
      return res.status(400).json({ error: 'Se requieren "producto" y "flete"' });
    }
    const r = calcularImportacionCourierSimple(producto, flete);

    if (userId) {
      const usuario = await User.findByPk(userId);
      if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });

      await Quote.create({
        user_id: userId,
        producto: Number(producto),
        flete: Number(flete),
        seguro: r.seguro,
        cif: r.cif,
        derechos_importacion: r.derechosImportacion,
        tasa_estadistica: r.tasaEstadistica,
        base_iva: r.baseIVA,
        iva: r.iva,
        total_impuestos: r.totalImpuestos,
        honorarios_courier: r.honorariosCourier,
        total_con_courier: r.totalConCourier,
        costo_final: r.costoFinal,
      });
    }

    res.json({ success: true, data: r });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

app.get('/users/:id/cotizaciones', async (req, res) => {
  try {
    const userId = Number(req.params.id);
    if (!Number.isFinite(userId)) return res.status(400).json({ error: 'id inválido' });

    const cotizaciones = await Quote.findAll({
      where: { user_id: userId },
      order: [['created_at', 'DESC']],
      attributes: [
        'id','producto','flete','seguro','cif',
        ['derechos_importacion','derechosImportacion'],
        ['tasa_estadistica','tasaEstadistica'],
        ['base_iva','baseIVA'],
        'iva',
        ['total_impuestos','totalImpuestos'],
        ['honorarios_courier','honorariosCourier'],
        ['total_con_courier','totalConCourier'],
        ['costo_final','costoFinal'],
        ['created_at','createdAt'],
      ],
    });

    res.json({ userId, cotizaciones });
  } catch (e) {
    res.status(500).json({ error: 'Error al consultar cotizaciones' });
  }
});


app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email y password requeridos' });

    const user = await User.findOne({ where: { email: String(email).toLowerCase() } });
    if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });

    const token = signToken({ id: user.id, email: user.email, name: user.name });

    // Opcional: devolver en cookie httpOnly + en body
    if (res.cookie) {
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        domain: process.env.COOKIE_DOMAIN || undefined, // e.g. "tudominio.com"
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7d
      });
    }

    return res.json({
      success: true,
      token, // si no quieres enviarlo en body, quítalo cuando uses cookie
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (e) {
    return res.status(500).json({ error: 'Error en login' });
  }
});

app.get('/health', (_req, res) => res.json({ status: 'OK' }));

// ---------- Arranque: conecta y crea tablas si no existen ----------
(async () => {
  try {
    await sequelize.authenticate();
    // crea/actualiza las tablas según los modelos
    await sequelize.sync({ alter: true }); // usa {force:false} por defecto; alter ajusta columnas si cambian
    app.listen(PORT, () => {
      console.log(`API escuchando en puerto ${PORT}`);
    });
  } catch (e) {
    console.error('Error inicializando DB:', e);
    process.exit(1);
  }
})();
