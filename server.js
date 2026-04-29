const express = require('express');
const cors = require('cors');
const basicAuth = require('express-basic-auth');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL manquante dans les variables d\'environnement');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ===================== SECURITY HELPERS =====================

function stripHtml(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/<[^>]*>/g, '').trim();
}

function sanitizeInput(obj) {
  if (typeof obj === 'string') return stripHtml(obj);
  if (Array.isArray(obj)) return obj.map(sanitizeInput);
  if (typeof obj === 'object' && obj !== null) {
    var result = {};
    for (var key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        result[key] = sanitizeInput(obj[key]);
      }
    }
    return result;
  }
  return obj;
}

function isValidPhone(phone) {
  return /^\d{10}$/.test(phone) && /^(07|05|01)/.test(phone);
}

function normalizePhone(phone) {
  return String(phone || '').replace(/\D/g, '').slice(0, 10);
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(String(password), salt, 100000, 64, 'sha256').toString('hex');
}

// ===================== MIDDLEWARE =====================

app.use(function(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.removeHeader('X-Powered-By');
  next();
});

var corsOptions = {
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type']
};

var limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Trop de requêtes, veuillez réessayer plus tard.' }
});

var apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: "Limite d'envoi atteinte. Veuillez patienter." }
});

app.use(function(req, res, next) {
  if (req.path === '/admin') {
    res.setHeader(
      'Content-Security-Policy',
      "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; script-src * data: blob: 'unsafe-inline' 'unsafe-eval'; style-src * data: blob: 'unsafe-inline'; connect-src * data: blob:; img-src * data: blob:; font-src * data: blob:;"
    );
  }
  next();
});

app.use(cors(corsOptions));
app.use(limiter);
app.use(express.json({ limit: '5mb' }));
app.use(function(req, res, next) {
  if (req.body && typeof req.body === 'object') req.body = sanitizeInput(req.body);
  next();
});

// ===================== DATABASE INIT =====================

var DEFAULT_SECTEURS = ['GRABO EST', 'GRABO EST 2', 'GRABO OUEST', 'GRABO OUEST 2', 'GNATO'];

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS lots (
      id SERIAL PRIMARY KEY,
      drenaet TEXT NOT NULL,
      iepp TEXT NOT NULL,
      secteur_pedagogique TEXT NOT NULL,
      nom_ecole TEXT NOT NULL,
      nom_directeur TEXT NOT NULL,
      prenoms_directeur TEXT NOT NULL,
      contact1 TEXT NOT NULL,
      contact2 TEXT,
      email TEXT,
      eleves JSONB NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS logs (
      id SERIAL PRIMARY KEY,
      action TEXT,
      details JSONB,
      ip_address TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS secteurs (
      id SERIAL PRIMARY KEY,
      nom TEXT NOT NULL UNIQUE
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ecoles (
      id SERIAL PRIMARY KEY,
      secteur_id INTEGER NOT NULL REFERENCES secteurs(id) ON DELETE CASCADE,
      nom TEXT NOT NULL,
      UNIQUE(secteur_id, nom)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS director_profiles (
      id SERIAL PRIMARY KEY,
      contact1 TEXT NOT NULL UNIQUE,
      nom_directeur TEXT NOT NULL,
      prenoms_directeur TEXT NOT NULL,
      nom_ecole TEXT NOT NULL,
      secteur_pedagogique TEXT NOT NULL,
      contact2 TEXT,
      email TEXT,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  for (const s of DEFAULT_SECTEURS) {
    await pool.query('INSERT INTO secteurs (nom) VALUES ($1) ON CONFLICT (nom) DO NOTHING', [s]);
  }

  console.log('✅ Tables PostgreSQL initialisées');
}

async function logAction(action, details, ip) {
  try {
    await pool.query('INSERT INTO logs (action, details, ip_address) VALUES ($1, $2, $3)', [action, details || {}, ip || '']);
  } catch (e) {
    console.error('Erreur logAction:', e.message);
  }
}

function validatePayload(data) {
  var errors = [];
  var requiredFields = ['drenaet', 'iepp', 'secteur_pedagogique', 'nom_ecole', 'nom_directeur', 'prenoms_directeur', 'contact1', 'eleves'];

  requiredFields.forEach(function(field) {
    if (!data[field] || String(data[field]).trim() === '') {
      errors.push('Champ requis manquant: ' + field);
    }
  });

  var fieldLimits = {
    drenaet: 100, iepp: 100, secteur_pedagogique: 100, nom_ecole: 200,
    nom_directeur: 100, prenoms_directeur: 200, contact1: 15, contact2: 15, email: 200
  };
  for (var fk in fieldLimits) {
    if (data[fk] && String(data[fk]).length > fieldLimits[fk]) {
      errors.push('Champ ' + fk + ' trop long (max ' + fieldLimits[fk] + ' caracteres)');
    }
  }

  if (data.contact1 && !isValidPhone(data.contact1)) {
    errors.push(/^\d{10}$/.test(data.contact1) ? 'Le contact 1 doit commencer par 07, 05 ou 01' : 'Le contact 1 doit contenir exactement 10 chiffres');
  }
  if (data.contact2 && data.contact2 !== '' && !isValidPhone(data.contact2)) {
    errors.push(/^\d{10}$/.test(data.contact2) ? 'Le contact 2 doit commencer par 07, 05 ou 01' : 'Le contact 2 doit contenir exactement 10 chiffres');
  }

  if (!Array.isArray(data.eleves)) {
    errors.push('Les eleves doivent etre un tableau');
  } else if (data.eleves.length > 500) {
    errors.push('Maximum 500 eleves par envoi');
  } else {
    data.eleves.forEach(function(eleve, idx) {
      var eleveRequired = ['nom', 'prenoms', 'sexe', 'nationalite', 'date_naissance_probable', 'classe', 'nom_pere', 'numero_pere', 'nom_mere', 'numero_mere', 'nom_temoin', 'numero_temoin'];
      eleveRequired.forEach(function(field) {
        if (!eleve[field] || String(eleve[field]).trim() === '') {
          errors.push('Eleve ' + (idx + 1) + ': champ manquant ' + field);
        }
      });
      if (eleve.date_naissance_probable && !/^\d{2}\/\d{2}\/\d{4}$/.test(eleve.date_naissance_probable)) {
        errors.push('Eleve ' + (idx + 1) + ': format date invalide (jj/mm/aaaa attendu)');
      }
      ['numero_pere', 'numero_mere', 'numero_temoin'].forEach(function(phoneField) {
        if (eleve[phoneField] && !isValidPhone(eleve[phoneField])) {
          errors.push(/^\d{10}$/.test(eleve[phoneField])
            ? 'Eleve ' + (idx + 1) + ': ' + phoneField + ' doit commencer par 07, 05 ou 01'
            : 'Eleve ' + (idx + 1) + ': ' + phoneField + ' doit contenir 10 chiffres');
        }
      });
      if (eleve.sexe && eleve.sexe !== 'G' && eleve.sexe !== 'F' && eleve.sexe !== 'M') {
        errors.push('Eleve ' + (idx + 1) + ': sexe invalide (G/F attendu)');
      }
      ['matricule', 'nationalite', 'cni_pere', 'cni_mere', 'cni_temoin'].forEach(function(optField) {
        if (eleve[optField] && String(eleve[optField]).length > 100) {
          errors.push('Eleve ' + (idx + 1) + ': ' + optField + ' trop long');
        }
      });
      if (eleve.sexe === 'M') {
        eleve.sexe = 'G';
      }
    });
  }
  return errors;
}

// ===================== ADMIN AUTH =====================

var adminPassword = process.env.ADMIN_PASSWORD || 'S3ph1r0th2025!';
app.use('/admin', basicAuth({ users: { admin: adminPassword }, challenge: true, realm: 'ACESE-Admin' }));

// ===================== ROUTES =====================

app.get('/admin', function(_, res) { res.sendFile(path.join(__dirname, 'admin.html')); });
app.get('/health', async function(_, res) {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', timestamp: new Date().toISOString(), db: 'postgres' });
  } catch (e) {
    res.status(500).json({ status: 'error', db: 'postgres', error: e.message });
  }
});
app.get('/api/ping', function(_, res) { res.json({ status: 'awake', timestamp: new Date().toISOString(), uptime: process.uptime() }); });

// Secteurs
app.get('/api/secteurs', async function(req, res) {
  try {
    const secteursRes = await pool.query('SELECT id, nom FROM secteurs ORDER BY nom');
    const secteurs = secteursRes.rows;
    const ecolesRes = await pool.query('SELECT id, secteur_id, nom FROM ecoles ORDER BY nom');
    const ecoles = ecolesRes.rows;
    const mapped = secteurs.map(s => ({ ...s, ecoles: ecoles.filter(e => e.secteur_id === s.id).map(e => ({ id: e.id, nom: e.nom })) }));
    res.json(mapped);
  } catch (err) {
    console.error('Erreur DB secteurs:', err);
    res.status(500).json({ error: 'Erreur base de donnees' });
  }
});

app.post('/api/secteurs', async function(req, res) {
  const nom = req.body.nom;
  if (!nom || nom.trim().length < 2 || nom.trim().length > 100) return res.status(400).json({ error: 'Nom du secteur requis (2-100 caracteres)' });
  try {
    const r = await pool.query('INSERT INTO secteurs (nom) VALUES ($1) RETURNING id, nom', [nom.trim()]);
    await logAction('ADD_SECTEUR', { nom: nom.trim() }, req.ip);
    res.status(201).json({ success: true, id: r.rows[0].id, nom: r.rows[0].nom });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Ce secteur existe deja' });
    res.status(500).json({ error: 'Erreur lors de l\'ajout' });
  }
});

app.delete('/api/secteurs/:id', async function(req, res) {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'ID invalide' });
  try {
    const r = await pool.query('DELETE FROM secteurs WHERE id = $1', [id]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Secteur non trouve' });
    await logAction('DELETE_SECTEUR', { id }, req.ip);
    res.json({ success: true, message: 'Secteur et ecoles supprimes' });
  } catch (err) {
    res.status(500).json({ error: 'Erreur de suppression' });
  }
});

app.post('/api/secteurs/:id/ecoles', async function(req, res) {
  const secteurId = parseInt(req.params.id);
  const nom = req.body.nom;
  if (isNaN(secteurId)) return res.status(400).json({ error: 'ID secteur invalide' });
  if (!nom || nom.trim().length < 2 || nom.trim().length > 200) return res.status(400).json({ error: 'Nom de l\'ecole requis (2-200 caracteres)' });
  try {
    const r = await pool.query('INSERT INTO ecoles (secteur_id, nom) VALUES ($1, $2) RETURNING id, nom', [secteurId, nom.trim()]);
    await logAction('ADD_ECOLE', { secteur_id: secteurId, nom: nom.trim() }, req.ip);
    res.status(201).json({ success: true, id: r.rows[0].id, nom: r.rows[0].nom });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Cette ecole existe deja dans ce secteur' });
    res.status(500).json({ error: 'Erreur lors de l\'ajout' });
  }
});

app.get('/api/secteurs/ecoles/count', async function(req, res) {
  try {
    const r = await pool.query('SELECT COUNT(*)::int as total FROM ecoles');
    res.json({ total: r.rows[0].total || 0 });
  } catch {
    res.status(500).json({ error: 'Erreur' });
  }
});

app.delete('/api/secteurs/:secteurId/ecoles/:ecoleId', async function(req, res) {
  const ecoleId = parseInt(req.params.ecoleId);
  if (isNaN(ecoleId)) return res.status(400).json({ error: 'ID invalide' });
  try {
    const r = await pool.query('DELETE FROM ecoles WHERE id = $1', [ecoleId]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Ecole non trouvee' });
    await logAction('DELETE_ECOLE', { id: ecoleId }, req.ip);
    res.json({ success: true, message: 'Ecole supprimee' });
  } catch {
    res.status(500).json({ error: 'Erreur de suppression' });
  }
});

// App config
app.get('/api/config', async function(req, res) {
  try {
    const r = await pool.query("SELECT key, value FROM app_config WHERE key IN ('contact_whatsapp', 'contact_email', 'contact_nom')");
    const config = {};
    r.rows.forEach(row => { config[row.key] = row.value; });
    res.json(config);
  } catch {
    res.status(500).json({ error: 'Erreur base de donnees' });
  }
});

app.put('/api/config', async function(req, res) {
  const updates = req.body;
  const allowedKeys = ['contact_whatsapp', 'contact_email', 'contact_nom'];
  const keysToUpdate = Object.keys(updates).filter(k => allowedKeys.includes(k));
  if (keysToUpdate.length === 0) return res.status(400).json({ error: 'Aucune cle valide' });
  try {
    for (const key of keysToUpdate) {
      const val = String(updates[key]).trim().substring(0, 200);
      await pool.query('INSERT INTO app_config (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value', [key, val]);
    }
    await logAction('UPDATE_CONFIG', { keys: keysToUpdate }, req.ip);
    res.json({ success: true });
  } catch (err) {
    console.error('Erreur config update:', err);
    res.status(500).json({ error: 'Erreur config' });
  }
});

// Director auth
app.post('/api/director-profile', async function(req, res) {
  const body = req.body || {};
  const contact1 = normalizePhone(body.contact1);
  const nomDirecteur = String(body.nom_directeur || '').trim();
  const prenomsDirecteur = String(body.prenoms_directeur || '').trim();
  const nomEcole = String(body.nom_ecole || '').trim();
  const secteurPedagogique = String(body.secteur_pedagogique || '').trim();
  const contact2 = normalizePhone(body.contact2);
  const email = String(body.email || '').trim().toLowerCase();
  const passwordHash = String(body.password_hash || '').trim();
  const passwordSalt = String(body.password_salt || '').trim();
  if (!contact1 || !nomDirecteur || !prenomsDirecteur || !nomEcole || !secteurPedagogique) return res.status(400).json({ error: 'Champs requis manquants' });
  if (!passwordHash || !passwordSalt) return res.status(400).json({ error: 'Mot de passe manquant' });
  try {
    await pool.query(
      'INSERT INTO director_profiles (contact1, nom_directeur, prenoms_directeur, nom_ecole, secteur_pedagogique, contact2, email, password_hash, password_salt, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP) ON CONFLICT(contact1) DO UPDATE SET nom_directeur=EXCLUDED.nom_directeur, prenoms_directeur=EXCLUDED.prenoms_directeur, nom_ecole=EXCLUDED.nom_ecole, secteur_pedagogique=EXCLUDED.secteur_pedagogique, contact2=EXCLUDED.contact2, email=EXCLUDED.email, password_hash=EXCLUDED.password_hash, password_salt=EXCLUDED.password_salt, updated_at=CURRENT_TIMESTAMP',
      [contact1, nomDirecteur, prenomsDirecteur, nomEcole, secteurPedagogique, contact2, email, passwordHash, passwordSalt]
    );
    await logAction('SAVE_DIRECTOR_PROFILE', { contact1, nom: nomDirecteur }, req.ip);
    res.json({ success: true });
  } catch (err) {
    console.error('Erreur directeur profile:', err);
    res.status(500).json({ error: 'Erreur enregistrement profil' });
  }
});

app.post('/api/director-recover', async function(req, res) {
  const body = req.body || {};
  const nomDirecteur = String(body.nom_directeur || '').trim().toUpperCase();
  const contact1 = normalizePhone(body.contact1);
  const nomEcole = String(body.nom_ecole || '').trim().toUpperCase();
  if (!nomDirecteur || !contact1) return res.status(400).json({ error: 'Nom et telephone requis' });
  try {
    const r = await pool.query('SELECT * FROM director_profiles WHERE contact1 = $1', [contact1]);
    const profile = r.rows.find(row => String(row.nom_directeur || '').trim().toUpperCase() === nomDirecteur && (!nomEcole || String(row.nom_ecole || '').trim().toUpperCase() === nomEcole));
    if (!profile) return res.status(404).json({ found: false, error: 'Aucun profil correspondant' });
    res.json({ found: true, contact1: profile.contact1, nom_directeur: profile.nom_directeur, prenoms_directeur: profile.prenoms_directeur, nom_ecole: profile.nom_ecole, secteur_pedagogique: profile.secteur_pedagogique });
  } catch {
    res.status(500).json({ error: 'Erreur base de donnees' });
  }
});

app.post('/api/director-verify', async function(req, res) {
  const body = req.body || {};
  const contact1 = normalizePhone(body.contact1);
  const password = String(body.password || '');
  if (!contact1 || !password) return res.status(400).json({ error: 'Donnees insuffisantes' });
  try {
    const r = await pool.query('SELECT * FROM director_profiles WHERE contact1 = $1', [contact1]);
    const profile = r.rows[0];
    if (!profile) return res.status(404).json({ valid: false });
    const computed = hashPassword(password, profile.password_salt);
    res.json({ valid: computed === profile.password_hash });
  } catch {
    res.status(500).json({ error: 'Erreur base de donnees' });
  }
});

// Duplicate check
app.post('/api/check-duplicate', async function(req, res) {
  const eleve = req.body;
  if (!eleve || !eleve.nom || !eleve.prenoms) return res.status(400).json({ error: 'Donnees insuffisantes' });
  const nom = eleve.nom.trim().toUpperCase();
  const prenoms = eleve.prenoms.trim().toUpperCase();
  try {
    const r = await pool.query('SELECT * FROM lots');
    const duplicates = [];
    r.rows.forEach(row => {
      const eleves = Array.isArray(row.eleves) ? row.eleves : [];
      eleves.forEach(existing => {
        const sameName = String(existing.nom || '').trim().toUpperCase() === nom && String(existing.prenoms || '').trim().toUpperCase() === prenoms;
        if (sameName) {
          duplicates.push({ id: row.id, ecole: row.nom_ecole, secteur: row.secteur_pedagogique, date: row.created_at, eleve: { nom: existing.nom, prenoms: existing.prenoms, classe: existing.classe, date_naissance_probable: existing.date_naissance_probable } });
        }
      });
    });
    res.json({ found: duplicates.length > 0, count: duplicates.length, duplicates });
  } catch {
    res.status(500).json({ error: 'Erreur base de donnees' });
  }
});

// Main data API
app.get('/api/eleves', async function(req, res) {
  const { secteur, ecole, dateDebut, dateFin } = req.query;
  let query = 'SELECT * FROM lots WHERE 1=1';
  const params = [];
  let idx = 1;
  if (secteur) { query += ` AND secteur_pedagogique = $${idx++}`; params.push(secteur); }
  if (ecole) { query += ` AND nom_ecole ILIKE $${idx++}`; params.push('%' + ecole + '%'); }
  if (dateDebut) { query += ` AND created_at >= $${idx++}`; params.push(dateDebut); }
  if (dateFin) { query += ` AND created_at <= $${idx++}`; params.push(dateFin + ' 23:59:59'); }
  query += ' ORDER BY created_at DESC';
  try {
    const r = await pool.query(query, params);
    res.json(r.rows);
  } catch (err) {
    console.error('Erreur DB:', err);
    res.status(500).json({ error: 'Erreur base de donnees' });
  }
});

app.get('/api/stats', async function(req, res) {
  try {
    const [parSecteur, parEcole, global] = await Promise.all([
      pool.query('SELECT secteur_pedagogique, COUNT(*)::int as nb_lots, COALESCE(SUM(jsonb_array_length(eleves)),0)::int as total_eleves FROM lots GROUP BY secteur_pedagogique'),
      pool.query('SELECT nom_ecole, secteur_pedagogique, COALESCE(SUM(jsonb_array_length(eleves)),0)::int as nb_eleves FROM lots GROUP BY nom_ecole, secteur_pedagogique ORDER BY nb_eleves DESC'),
      pool.query('SELECT COUNT(DISTINCT id)::int as total_lots, COALESCE(SUM(jsonb_array_length(eleves)),0)::int as total_eleves, COUNT(DISTINCT nom_ecole)::int as total_ecoles, COUNT(DISTINCT secteur_pedagogique)::int as total_secteurs FROM lots')
    ]);

    const parClasse = await pool.query("SELECT value->>'classe' as classe, COUNT(*)::int as effectif FROM lots, jsonb_array_elements(eleves) AS value GROUP BY value->>'classe'");

    res.json({
      parSecteur: parSecteur.rows,
      parEcole: parEcole.rows,
      parClasse: parClasse.rows,
      global: global.rows,
    });
  } catch (err) {
    console.error('Erreur stats:', err);
    res.status(500).json({ error: 'Erreur base de donnees' });
  }
});

app.post('/api/eleves', apiLimiter, async function(req, res) {
  const ip = req.ip || req.connection.remoteAddress;
  const errors = validatePayload(req.body);
  if (errors.length > 0) {
    await logAction('VALIDATION_FAILED', { errors }, ip);
    return res.status(400).json({ error: 'Validation echouee', details: errors });
  }

  const { drenaet, iepp, secteur_pedagogique, nom_ecole, nom_directeur, prenoms_directeur, contact1, contact2, email, eleves } = req.body;
  try {
    const r = await pool.query(
      'INSERT INTO lots (drenaet, iepp, secteur_pedagogique, nom_ecole, nom_directeur, prenoms_directeur, contact1, contact2, email, eleves) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id',
      [drenaet, iepp, secteur_pedagogique, nom_ecole, nom_directeur, prenoms_directeur, contact1, contact2 || '', email ? email.toLowerCase() : '', JSON.stringify(eleves)]
    );
    await logAction('INSERT_SUCCESS', { id: r.rows[0].id, ecole: nom_ecole, nb_eleves: eleves.length }, ip);
    res.status(201).json({ success: true, id: r.rows[0].id, message: eleves.length + ' eleve(s) enregistre(s) avec succes' });
  } catch (err) {
    console.error('Erreur insertion:', err);
    await logAction('INSERT_ERROR', { error: err.message }, ip);
    res.status(500).json({ error: "Erreur lors de l'enregistrement" });
  }
});

app.delete('/api/eleves/:id', async function(req, res) {
  const id = parseInt(req.params.id);
  const ip = req.ip || req.connection.remoteAddress;
  if (isNaN(id)) return res.status(400).json({ error: 'ID invalide' });
  try {
    const r = await pool.query('DELETE FROM lots WHERE id = $1', [id]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Lot non trouve' });
    await logAction('DELETE', { id }, ip);
    res.json({ success: true, message: 'Lot supprime' });
  } catch {
    res.status(500).json({ error: 'Erreur de suppression' });
  }
});

app.get('/api/logs', async function(req, res) {
  let limit = parseInt(req.query.limit) || 100;
  if (limit > 1000) limit = 1000;
  try {
    const r = await pool.query('SELECT * FROM logs ORDER BY created_at DESC LIMIT $1', [limit]);
    res.json(r.rows);
  } catch {
    res.status(500).json({ error: 'Erreur base de donnees' });
  }
});

// Backup / restore (JSON)
app.get('/api/backup/download', async function(req, res) {
  try {
    const [lots, logs, config, secteurs, ecoles, directors] = await Promise.all([
      pool.query('SELECT * FROM lots ORDER BY id ASC'),
      pool.query('SELECT * FROM logs ORDER BY id ASC'),
      pool.query('SELECT * FROM app_config'),
      pool.query('SELECT * FROM secteurs'),
      pool.query('SELECT * FROM ecoles'),
      pool.query('SELECT * FROM director_profiles'),
    ]);
    const backup = { version: '4.0-postgres', exported_at: new Date().toISOString(), lots: lots.rows, logs: logs.rows, config: config.rows, secteurs: secteurs.rows, ecoles: ecoles.rows, director_profiles: directors.rows };
    const filename = 'ACESE_backup_' + new Date().toISOString().split('T')[0] + '.json';
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.json(backup);
  } catch (err) {
    res.status(500).json({ error: 'Erreur sauvegarde' });
  }
});

app.post('/api/backup/restore', async function(req, res) {
  const backup = req.body;
  if (!backup || !backup.lots) return res.status(400).json({ error: 'Fichier de sauvegarde invalide' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM ecoles');
    await client.query('DELETE FROM lots');
    await client.query('DELETE FROM logs');
    await client.query('DELETE FROM app_config');
    await client.query('DELETE FROM director_profiles');
    await client.query('DELETE FROM secteurs');

    for (const s of (backup.secteurs || [])) {
      await client.query('INSERT INTO secteurs (id, nom) VALUES ($1,$2) ON CONFLICT (id) DO NOTHING', [s.id, s.nom]);
    }
    for (const e of (backup.ecoles || [])) {
      await client.query('INSERT INTO ecoles (id, secteur_id, nom) VALUES ($1,$2,$3) ON CONFLICT (id) DO NOTHING', [e.id, e.secteur_id, e.nom]);
    }
    for (const c of (backup.config || [])) {
      await client.query('INSERT INTO app_config (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value', [c.key, c.value]);
    }
    for (const d of (backup.director_profiles || [])) {
      await client.query('INSERT INTO director_profiles (id, contact1, nom_directeur, prenoms_directeur, nom_ecole, secteur_pedagogique, contact2, email, password_hash, password_salt, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (contact1) DO UPDATE SET nom_directeur=EXCLUDED.nom_directeur, prenoms_directeur=EXCLUDED.prenoms_directeur, nom_ecole=EXCLUDED.nom_ecole, secteur_pedagogique=EXCLUDED.secteur_pedagogique, contact2=EXCLUDED.contact2, email=EXCLUDED.email, password_hash=EXCLUDED.password_hash, password_salt=EXCLUDED.password_salt, updated_at=EXCLUDED.updated_at', [d.id, d.contact1, d.nom_directeur, d.prenoms_directeur, d.nom_ecole, d.secteur_pedagogique, d.contact2, d.email, d.password_hash, d.password_salt, d.created_at, d.updated_at]);
    }
    for (const lot of (backup.lots || [])) {
      await client.query('INSERT INTO lots (id, drenaet, iepp, secteur_pedagogique, nom_ecole, nom_directeur, prenoms_directeur, contact1, contact2, email, eleves, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)', [lot.id, lot.drenaet, lot.iepp, lot.secteur_pedagogique, lot.nom_ecole, lot.nom_directeur, lot.prenoms_directeur, lot.contact1, lot.contact2 || '', lot.email || '', JSON.stringify(lot.eleves || []), lot.created_at, lot.updated_at]);
    }
    for (const lg of (backup.logs || [])) {
      await client.query('INSERT INTO logs (id, action, details, ip_address, created_at) VALUES ($1,$2,$3,$4,$5)', [lg.id, lg.action, lg.details || {}, lg.ip_address, lg.created_at]);
    }
    await client.query('COMMIT');
    await logAction('RESTORE_BACKUP', { lots_restored: (backup.lots || []).length }, req.ip);
    res.json({ success: true, lots_restored: (backup.lots || []).length });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Restore error:', err);
    res.status(500).json({ error: 'Erreur restauration' });
  } finally {
    client.release();
  }
});

app.get('/api/backup/stats', async function(req, res) {
  try {
    const r = await pool.query('SELECT COUNT(*)::int as total_lots, COALESCE(SUM(jsonb_array_length(eleves)),0)::int as total_eleves FROM lots');
    res.json({ total_lots: r.rows[0].total_lots || 0, total_eleves: r.rows[0].total_eleves || 0, last_backup_hint: 'Téléchargez une sauvegarde depuis /admin ou /api/backup/download' });
  } catch {
    res.status(500).json({ error: 'Erreur' });
  }
});

// Keep-awake
var PING_INTERVAL = 13 * 60 * 1000;
function selfPing() {
  var url = 'http://localhost:' + PORT + '/health';
  require('http').get(url, function() {
    console.log('[' + new Date().toISOString() + '] Keep-alive ping OK (uptime: ' + Math.round(process.uptime()) + 's)');
  }).on('error', function(err) {
    console.error('[' + new Date().toISOString() + '] Keep-alive ping failed:', err.message);
  });
}
setTimeout(function() { selfPing(); setInterval(selfPing, PING_INTERVAL); }, 60000);

// Start
initDatabase()
  .then(() => {
    app.listen(PORT, function() {
      console.log(
        '\n  ======================================================\n' +
        '  |       ACESE - IEPP GRABO (Serveur Admin)          |\n' +
        '  ======================================================\n' +
        '  |  PostgreSQL connecté                              |\n' +
        '  |  Serveur demarre sur le port ' + PORT + '                |\n' +
        '  |  Dashboard: http://localhost:' + PORT + '/admin            |\n' +
        '  |  API:       http://localhost:' + PORT + '/api/eleves       |\n' +
        '  |  Secteurs:  http://localhost:' + PORT + '/api/secteurs     |\n' +
        '  |  Health:    http://localhost:' + PORT + '/health           |\n' +
        '  ======================================================\n'
      );
    });
  })
  .catch((err) => {
    console.error('❌ Erreur initialisation PostgreSQL:', err);
    process.exit(1);
  });
