


// api/index.js
const express = require('express');
const bcrypt = require('bcryptjs'); 
const { Sequelize, DataTypes } = require('sequelize');
const jwt = require('jsonwebtoken');
const path = require("path");
const app = express();
app.set('trust proxy', 1);
app.use(express.json());

const cors = require('cors');

app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));

app.use(
  "/",
  express.static(path.join(__dirname, "public"))
);

// en Express 5 usa regex o '/*' en lugar de '*'
app.options(/.*/, cors());  

// ===== Config inline (NO .env) =====
const JWT_SECRET  = 'reemplaza-por-una-clave-bien-larga-y-unica-32+chars';
const JWT_EXPIRES = '7d';

// ========= NEON: usa pooler + SSL =========
const DB_NAME = 'neondb';
const DB_USER = 'neondb_owner';
const DB_PASS = 'npg_xS3TXWR2cmwi';
const DB_HOST = 'ep-old-unit-ac862egj-pooler.sa-east-1.aws.neon.tech';
const DB_PORT = 5432;

// Cache global para serverless (evita reconectar en cada invocación)
let sequelize = global.__sequelize;
if (!sequelize) {
  sequelize = new Sequelize(DB_NAME, DB_USER, DB_PASS, {
    host: DB_HOST,
    port: DB_PORT,
    dialect: 'postgres',
    logging: false,
    pool: { max: 5, idle: 30000 }, // más chico en serverless
    dialectOptions: { ssl: { require: true } }
  });
  global.__sequelize = sequelize;
}

// ===== Modelos =====
let User = global.__User;
let Quote = global.__Quote;
if (!User || !Quote) {
  User = sequelize.define('User', {
    id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
    name: { type: DataTypes.TEXT, allowNull: false },
    email: { type: DataTypes.TEXT, allowNull: false, unique: true },
    password_hash: { type: DataTypes.TEXT, allowNull: false },
  }, { tableName: 'users', timestamps: true, createdAt: 'created_at', updatedAt: false });

  Quote = sequelize.define('Quote', {
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
  }, { tableName: 'quotes', timestamps: true, createdAt: 'created_at', updatedAt: false });

  User.hasMany(Quote, { foreignKey: 'user_id' });
  Quote.belongsTo(User, { foreignKey: 'user_id' });

  global.__User = User;
  global.__Quote = Quote;
}

// Init DB una sola vez por instancia
let initPromise = global.__initPromise;
if (!initPromise) {
  initPromise = (async () => {
    await sequelize.authenticate();
    await sequelize.sync({ alter: true });
  })();
  global.__initPromise = initPromise;
}

// ===== Negocio =====
const DER_IMPORT_PCT = 0.16;
const TASA_ESTAD_PCT = 0.03;
const IVA_PCT        = 0.21;
const SEGURO_PCT     = 0.01;
const HONORARIOS     = 60;
const r2 = (x) => Math.round((x + Number.EPSILON) * 100) / 100;

function calcularImportacionCourierSimple(producto, flete) {
  const P = Number(producto); const F = Number(flete);
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
  return { seguro, cif, derechosImportacion, tasaEstadistica, baseIVA, iva, totalImpuestos, honorariosCourier: HONORARIOS, totalConCourier, costoFinal };
}

// ===== Auth (Bearer simple) =====
function signToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES }); }
function auth(req, res, next) {
  try {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'No autenticado' });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { return res.status(401).json({ error: 'Token inválido o expirado' }); }
}


const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
const SHEET_CSV_URL = process.env.SHEET_CSV_URL || 'https://docs.google.com/spreadsheets/d/1SoqoRRihCpr-fOHmfyuC-Yp99bpn3aKYmU1mgeEy9pU/export?format=csv&gid=0';

async function isEmailInSheet(email) {
  const res = await fetch(SHEET_CSV_URL);
  const csv = await res.text();
  const lines = csv.split(/\r?\n/);
  const needle = String(email).trim().toLowerCase();
  return lines.some(line => line.split(',')[0].replace(/(^"|"$)/g,'').trim().toLowerCase() === needle);
}


// ===== Rutas =====
app.get('/health', async (_req, res) => {
  try { await initPromise; res.json({ status: 'OK' }); }
  catch (e) { res.status(500).json({ status: 'DB_ERROR', error: String(e) }); }
});

/* app.post('/users', async (req, res) => {
  try {
    await initPromise;
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ error: 'name, email y password son requeridos' });
    const password_hash = await bcrypt.hash(password, 10);

    const user = await User.create({ name, email: String(email).toLowerCase(), password_hash });
    res.status(201).json({ id: user.id, name: user.name, email: user.email });
  } catch (err) {
    if (String(err).includes('unique')) return res.status(409).json({ error: 'El email ya está registrado' });
    res.status(500).json({ error: 'Error al crear usuario' });
  }
});
 */

app.post('/users', async (req, res) => {
  try {
    await initPromise;
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name, email y password son requeridos' });
    }

    // ✅ Chequeo en Google Sheets
    const permitido = await isEmailInSheet(email);
    if (!permitido) {
      return res.status(403).json({ error: 'El email no está autorizado (no figura en la lista).' });
    }

    const password_hash = await bcrypt.hash(password, 10);
    const user = await User.create({
      name,
      email: String(email).toLowerCase(),
      password_hash,
    });
    res.status(201).json({ id: user.id, name: user.name, email: user.email });
  } catch (err) {
    if (String(err).includes('unique')) {
      return res.status(409).json({ error: 'El email ya está registrado' });
    }
    console.error('Error /users:', err);
    res.status(500).json({ error: 'Error al crear usuario' });
  }
});

app.post('/login', async (req, res) => {
  try {
    await initPromise;
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email y password requeridos' });
    const user = await User.findOne({ where: { email: String(email).toLowerCase() } });
    if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });
    const token = signToken({ id: user.id, email: user.email, name: user.name });
    res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email } });
  } catch { res.status(500).json({ error: 'Error en login' }); }
});

app.get('/me', auth, async (req, res) => {
  await initPromise;
  const user = await User.findByPk(req.user.id, { attributes: ['id','name','email','created_at'] });
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json({ user });
});

app.post('/calcular-importacion', async (req, res) => {
  try {
    await initPromise;
    const { producto, flete, userId } = req.body || {};
    if (producto === undefined || flete === undefined) return res.status(400).json({ error: 'Se requieren "producto" y "flete"' });
    const r = calcularImportacionCourierSimple(producto, flete);
    if (userId) {
      const usuario = await User.findByPk(userId);
      if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });
      await Quote.create({
        user_id: userId, producto: Number(producto), flete: Number(flete),
        seguro: r.seguro, cif: r.cif, derechos_importacion: r.derechosImportacion,
        tasa_estadistica: r.tasaEstadistica, base_iva: r.baseIVA, iva: r.iva,
        total_impuestos: r.totalImpuestos, honorarios_courier: r.honorariosCourier,
        total_con_courier: r.totalConCourier, costo_final: r.costoFinal,
      });
    }
    res.json({ success: true, data: r });
  } catch (error) { res.status(400).json({ success: false, error: error.message }); }
});

app.get('/users/:id/cotizaciones', async (req, res) => {
  try {
    await initPromise;

    const userId = Number(req.params.id);
    if (!Number.isFinite(userId)) {
      return res.status(400).json({ error: 'id inválido' });
    }

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
    console.error('Error /users/:id/cotizaciones:', e);
    res.status(500).json({ error: 'Error al consultar cotizaciones' });
  }
});


if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`API escuchando en puerto ${PORT}`);
  });
}
// Exporta el app (Vercel lo usa como handler)
module.exports = app;
