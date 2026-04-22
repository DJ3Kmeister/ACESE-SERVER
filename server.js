const express = require('express');
const cors = require('cors');
const basicAuth = require('express-basic-auth');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 10000;
const dbFile = process.env.DB_FILE || 'collecte.db';
const db = new sqlite3.Database(dbFile);

// ===================== SECURITY HELPERS =====================

// Strip HTML tags to prevent XSS
function stripHtml(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/<[^>]*>/g, '').trim();
}

// Sanitize an object recursively
function sanitizeInput(obj) {
  if (typeof obj === 'string') return stripHtml(obj);
  if (Array.isArray(obj)) return obj.map(sanitizeInput);
  if (typeof obj === 'object' && obj !== null) {
    var result = {};
    for (var key in obj) {
      if (obj.hasOwnProperty(key)) {
        result[key] = sanitizeInput(obj[key]);
      }
    }
    return result;
  }
  return obj;
}

// Validate phone: 10 digits starting with 07, 05, or 01
function isValidPhone(phone) {
  return /^\d{10}$/.test(phone) && /^(07|05|01)/.test(phone);
}

// ===================== MIDDLEWARE =====================

// Security headers
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
  methods: ['GET', 'POST', 'DELETE'],
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

// CSP for admin page
app.use(function(req, res, next) {
  if (req.path === '/admin') {
    res.setHeader(
      "Content-Security-Policy",
      "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; " +
      "script-src * data: blob: 'unsafe-inline' 'unsafe-eval'; " +
      "style-src * data: blob: 'unsafe-inline'; " +
      "connect-src * data: blob:; " +
      "img-src * data: blob:; " +
      "font-src * data: blob:;"
    );
  }
  next();
});

app.use(cors(corsOptions));
app.use(limiter);
app.use(express.json({ limit: '5mb' }));

// Sanitize all incoming JSON body
app.use(function(req, res, next) {
  if (req.body && typeof req.body === 'object') {
    req.body = sanitizeInput(req.body);
  }
  next();
});

// ===================== DATABASE =====================

var DEFAULT_SECTEURS = ['GRABO EST', 'GRABO EST 2', 'GRABO OUEST', 'GRABO OUEST 2', 'GNATO'];

db.serialize(function() {
  db.run("CREATE TABLE IF NOT EXISTS lots (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "drenaet TEXT NOT NULL," +
    "iepp TEXT NOT NULL," +
    "secteur_pedagogique TEXT NOT NULL," +
    "nom_ecole TEXT NOT NULL," +
    "nom_directeur TEXT NOT NULL," +
    "prenoms_directeur TEXT NOT NULL," +
    "contact1 TEXT NOT NULL," +
    "contact2 TEXT," +
    "email TEXT," +
    "eleves TEXT NOT NULL," +
    "created_at DATETIME DEFAULT CURRENT_TIMESTAMP," +
    "updated_at DATETIME DEFAULT CURRENT_TIMESTAMP" +
  ")");

  db.run("CREATE TABLE IF NOT EXISTS logs (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "action TEXT," +
    "details TEXT," +
    "ip_address TEXT," +
    "created_at DATETIME DEFAULT CURRENT_TIMESTAMP" +
  ")");

  db.run("CREATE TABLE IF NOT EXISTS secteurs (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "nom TEXT NOT NULL UNIQUE" +
  ")");

  db.run("CREATE TABLE IF NOT EXISTS ecoles (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "secteur_id INTEGER NOT NULL," +
    "nom TEXT NOT NULL," +
    "FOREIGN KEY (secteur_id) REFERENCES secteurs(id) ON DELETE CASCADE," +
    "UNIQUE(secteur_id, nom)" +
  ")");

  db.run("CREATE TABLE IF NOT EXISTS app_config (" +
    "key TEXT PRIMARY KEY," +
    "value TEXT NOT NULL" +
  ")");

  // Seed default secteurs
  DEFAULT_SECTEURS.forEach(function(s) {
    db.run('INSERT OR IGNORE INTO secteurs (nom) VALUES (?)', [s]);
  });
});

// ===================== HELPERS =====================

function validatePayload(data) {
  var errors = [];
  var requiredFields = ['drenaet', 'iepp', 'secteur_pedagogique', 'nom_ecole',
    'nom_directeur', 'prenoms_directeur', 'contact1', 'eleves'];

  requiredFields.forEach(function(field) {
    if (!data[field] || String(data[field]).trim() === '') {
      errors.push('Champ requis manquant: ' + field);
    }
  });

  // Length limits
  var fieldLimits = {
    drenaet: 100, iepp: 100, secteur_pedagogique: 100, nom_ecole: 200,
    nom_directeur: 100, prenoms_directeur: 200, contact1: 15, contact2: 15, email: 200
  };
  for (var fk in fieldLimits) {
    if (data[fk] && String(data[fk]).length > fieldLimits[fk]) {
      errors.push('Champ ' + fk + ' trop long (max ' + fieldLimits[fk] + ' caracteres)');
    }
  }

  // Phone validation
  if (data.contact1 && !isValidPhone(data.contact1)) {
    if (!/^\d{10}$/.test(data.contact1)) {
      errors.push('Le contact 1 doit contenir exactement 10 chiffres');
    } else {
      errors.push('Le contact 1 doit commencer par 07, 05 ou 01');
    }
  }
  if (data.contact2 && data.contact2 !== '') {
    if (!isValidPhone(data.contact2)) {
      if (!/^\d{10}$/.test(data.contact2)) {
        errors.push('Le contact 2 doit contenir exactement 10 chiffres');
      } else {
        errors.push('Le contact 2 doit commencer par 07, 05 ou 01');
      }
    }
  }

  if (!Array.isArray(data.eleves)) {
    errors.push('Les eleves doivent etre un tableau');
  } else if (data.eleves.length > 500) {
    errors.push('Maximum 500 eleves par envoi');
  } else {
    data.eleves.forEach(function(eleve, idx) {
      var eleveRequired = ['nom', 'prenoms', 'sexe', 'date_naissance_probable', 'classe',
        'nom_pere', 'numero_pere', 'nom_mere', 'numero_mere', 'nom_temoin', 'numero_temoin'];
      eleveRequired.forEach(function(field) {
        if (!eleve[field] || String(eleve[field]).trim() === '') {
          errors.push('Eleve ' + (idx + 1) + ': champ manquant ' + field);
        }
      });
      if (eleve.date_naissance_probable && !/^\d{2}\/\d{2}\/\d{4}$/.test(eleve.date_naissance_probable)) {
        errors.push('Eleve ' + (idx + 1) + ': format date invalide (jj/mm/aaaa attendu)');
      }
      // Validate student phones
      ['numero_pere', 'numero_mere', 'numero_temoin'].forEach(function(phoneField) {
        if (eleve[phoneField] && !isValidPhone(eleve[phoneField])) {
          if (!/^\d{10}$/.test(eleve[phoneField])) {
            errors.push('Eleve ' + (idx + 1) + ': ' + phoneField + ' doit contenir 10 chiffres');
          } else {
            errors.push('Eleve ' + (idx + 1) + ': ' + phoneField + ' doit commencer par 07, 05 ou 01');
          }
        }
      });
      // Validate sexe
      if (eleve.sexe && eleve.sexe !== 'M' && eleve.sexe !== 'F') {
        errors.push('Eleve ' + (idx + 1) + ': sexe invalide');
      }
    });
  }
  return errors;
}

function logAction(action, details, ip) {
  db.run('INSERT INTO logs (action, details, ip_address) VALUES (?, ?, ?)',
    [action, JSON.stringify(details), ip]);
}

// ===================== ADMIN AUTH =====================

var adminPassword = process.env.ADMIN_PASSWORD || 'S3ph1r0th2025!';
app.use('/admin', basicAuth({
  users: { admin: adminPassword },
  challenge: true,
  realm: 'ACESE-Admin'
}));

// ===================== ROUTES =====================

// Admin dashboard
app.get('/admin', function(_, res) {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Health check
app.get('/health', function(_, res) {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Keep-alive ping
app.get('/api/ping', function(_, res) {
  res.json({ status: 'awake', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

// ===================== SECTEURS & ECOLES API =====================

// GET all secteurs with their ecoles (public)
app.get('/api/secteurs', function(req, res) {
  db.all('SELECT id, nom FROM secteurs ORDER BY nom', [], function(err, secteurs) {
    if (err) {
      console.error('Erreur DB secteurs:', err);
      return res.status(500).json({ error: 'Erreur base de donnees' });
    }

    if (secteurs.length === 0) {
      return res.json([]);
    }

    var completed = 0;
    secteurs.forEach(function(s, idx) {
      db.all('SELECT id, nom FROM ecoles WHERE secteur_id = ? ORDER BY nom', [s.id], function(err2, ecoles) {
        secteurs[idx].ecoles = err2 ? [] : (ecoles || []);
        completed++;
        if (completed === secteurs.length) {
          res.json(secteurs);
        }
      });
    });
  });
});

// POST add secteur (admin only)
app.post('/api/secteurs', function(req, res) {
  var nom = req.body.nom;
  if (!nom || nom.trim().length < 2 || nom.trim().length > 100) {
    return res.status(400).json({ error: 'Nom du secteur requis (2-100 caracteres)' });
  }

  db.run('INSERT INTO secteurs (nom) VALUES (?)', [nom.trim()], function(err) {
    if (err) {
      if (err.message.includes('UNIQUE')) {
        return res.status(409).json({ error: 'Ce secteur existe deja' });
      }
      return res.status(500).json({ error: 'Erreur lors de l\'ajout' });
    }
    logAction('ADD_SECTEUR', { nom: nom.trim() }, req.ip);
    res.status(201).json({ success: true, id: this.lastID, nom: nom.trim() });
  });
});

// DELETE secteur (admin only)
app.delete('/api/secteurs/:id', function(req, res) {
  var id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'ID invalide' });

  // Delete ecoles first
  db.run('DELETE FROM ecoles WHERE secteur_id = ?', [id], function() {
    db.run('DELETE FROM secteurs WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ error: 'Erreur de suppression' });
      if (this.changes === 0) return res.status(404).json({ error: 'Secteur non trouve' });
      logAction('DELETE_SECTEUR', { id: id }, req.ip);
      res.json({ success: true, message: 'Secteur et ecoles supprimes' });
    });
  });
});

// POST add ecole to secteur (admin only)
app.post('/api/secteurs/:id/ecoles', function(req, res) {
  var secteurId = parseInt(req.params.id);
  var nom = req.body.nom;
  if (isNaN(secteurId)) return res.status(400).json({ error: 'ID secteur invalide' });
  if (!nom || nom.trim().length < 2 || nom.trim().length > 200) {
    return res.status(400).json({ error: 'Nom de l\'ecole requis (2-200 caracteres)' });
  }

  db.run('INSERT INTO ecoles (secteur_id, nom) VALUES (?, ?)', [secteurId, nom.trim()], function(err) {
    if (err) {
      if (err.message.includes('UNIQUE')) {
        return res.status(409).json({ error: 'Cette ecole existe deja dans ce secteur' });
      }
      return res.status(500).json({ error: 'Erreur lors de l\'ajout' });
    }
    logAction('ADD_ECOLE', { secteur_id: secteurId, nom: nom.trim() }, req.ip);
    res.status(201).json({ success: true, id: this.lastID, nom: nom.trim() });
  });
});

// DELETE ecole (admin only)
app.delete('/api/secteurs/:secteurId/ecoles/:ecoleId', function(req, res) {
  var ecoleId = parseInt(req.params.ecoleId);
  if (isNaN(ecoleId)) return res.status(400).json({ error: 'ID invalide' });

  db.run('DELETE FROM ecoles WHERE id = ?', [ecoleId], function(err) {
    if (err) return res.status(500).json({ error: 'Erreur de suppression' });
    if (this.changes === 0) return res.status(404).json({ error: 'Ecole non trouvee' });
    logAction('DELETE_ECOLE', { id: ecoleId }, req.ip);
    res.json({ success: true, message: 'Ecole supprimee' });
  });
});

// ===================== APP CONFIG API (contacts, etc) =====================

// GET app config (public — used by client for contact info)
app.get('/api/config', function(req, res) {
  db.all("SELECT key, value FROM app_config WHERE key IN ('contact_whatsapp', 'contact_email', 'contact_nom')", [], function(err, rows) {
    if (err) return res.status(500).json({ error: 'Erreur base de donnees' });
    var config = {};
    rows.forEach(function(r) { config[r.key] = r.value; });
    res.json(config);
  });
});

// PUT app config (admin only)
app.put('/api/config', function(req, res) {
  var updates = req.body;
  var allowedKeys = ['contact_whatsapp', 'contact_email', 'contact_nom'];
  var completed = 0;
  var keysToUpdate = Object.keys(updates).filter(function(k) { return allowedKeys.indexOf(k) !== -1; });

  if (keysToUpdate.length === 0) {
    return res.status(400).json({ error: 'Aucune cle valide' });
  }

  keysToUpdate.forEach(function(key) {
    var val = String(updates[key]).trim().substring(0, 200);
    db.run("INSERT INTO app_config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
      [key, val, val], function(err) {
        if (err) console.error('Erreur config update:', err);
        completed++;
        if (completed === keysToUpdate.length) {
          logAction('UPDATE_CONFIG', { keys: keysToUpdate }, req.ip);
          res.json({ success: true });
        }
      });
  });
});

// ===================== DUPLICATE CHECK =====================

// Check if a student already exists (by name + parents/witness)
app.post('/api/check-duplicate', function(req, res) {
  var eleve = req.body;

  if (!eleve || !eleve.nom || !eleve.prenoms) {
    return res.status(400).json({ error: 'Donnees insuffisantes' });
  }

  var nom = eleve.nom.trim().toUpperCase();
  var prenoms = eleve.prenoms.trim().toUpperCase();

  // Search in all lots for matching student
  db.all('SELECT lots.* FROM lots', [], function(err, rows) {
    if (err) return res.status(500).json({ error: 'Erreur base de donnees' });

    var duplicates = [];

    rows.forEach(function(row) {
      var eleves = [];
      try { eleves = JSON.parse(row.eleves || '[]'); } catch(e) { eleves = []; }

      eleves.forEach(function(existing) {
        // Match by full name (case-insensitive)
        var sameName = existing.nom.trim().toUpperCase() === nom &&
                       existing.prenoms.trim().toUpperCase() === prenoms;

        if (sameName) {
          duplicates.push({
            id: row.id,
            ecole: row.nom_ecole,
            secteur: row.secteur_pedagogique,
            date: row.created_at,
            eleve: {
              nom: existing.nom,
              prenoms: existing.prenoms,
              classe: existing.classe,
              date_naissance_probable: existing.date_naissance_probable
            }
          });
        }
      });
    });

    res.json({
      found: duplicates.length > 0,
      count: duplicates.length,
      duplicates: duplicates
    });
  });
});

// ===================== MAIN DATA API =====================

// GET all lots with filters
app.get('/api/eleves', function(req, res) {
  var secteur = req.query.secteur;
  var ecole = req.query.ecole;
  var dateDebut = req.query.dateDebut;
  var dateFin = req.query.dateFin;
  var query = 'SELECT * FROM lots WHERE 1=1';
  var params = [];

  if (secteur) { query += ' AND secteur_pedagogique = ?'; params.push(secteur); }
  if (ecole) { query += ' AND nom_ecole LIKE ?'; params.push('%' + ecole + '%'); }
  if (dateDebut) { query += ' AND created_at >= ?'; params.push(dateDebut); }
  if (dateFin) { query += ' AND created_at <= ?'; params.push(dateFin + ' 23:59:59'); }

  query += ' ORDER BY created_at DESC';

  db.all(query, params, function(err, rows) {
    if (err) {
      console.error('Erreur DB:', err);
      return res.status(500).json({ error: 'Erreur base de donnees' });
    }
    res.json(rows);
  });
});

// GET statistics
app.get('/api/stats', function(req, res) {
  var queries = {
    parSecteur: "SELECT secteur_pedagogique, COUNT(*) as nb_lots, " +
      "SUM(CASE WHEN eleves IS NOT NULL THEN json_array_length(eleves) ELSE 0 END) as total_eleves " +
      "FROM lots GROUP BY secteur_pedagogique",
    parEcole: "SELECT nom_ecole, secteur_pedagogique, " +
      "SUM(CASE WHEN eleves IS NOT NULL THEN json_array_length(eleves) ELSE 0 END) as nb_eleves " +
      "FROM lots GROUP BY nom_ecole ORDER BY nb_eleves DESC",
    parClasse: "SELECT json_extract(value, '$.classe') as classe, COUNT(*) as effectif " +
      "FROM lots, json_each(lots.eleves) GROUP BY classe",
    global: "SELECT COUNT(DISTINCT lots.id) as total_lots, " +
      "SUM(CASE WHEN eleves IS NOT NULL THEN json_array_length(eleves) ELSE 0 END) as total_eleves, " +
      "COUNT(DISTINCT nom_ecole) as total_ecoles, " +
      "COUNT(DISTINCT secteur_pedagogique) as total_secteurs FROM lots"
  };

  var results = {};
  var completed = 0;

  Object.entries(queries).forEach(function(entry) {
    var key = entry[0];
    var query = entry[1];
    db.all(query, [], function(err, rows) {
      results[key] = err ? { error: err.message } : rows;
      completed++;
      if (completed === Object.keys(queries).length) {
        res.json(results);
      }
    });
  });
});

// POST add students
app.post('/api/eleves', apiLimiter, function(req, res) {
  var ip = req.ip || req.connection.remoteAddress;

  var errors = validatePayload(req.body);
  if (errors.length > 0) {
    logAction('VALIDATION_FAILED', { errors: errors }, ip);
    return res.status(400).json({ error: 'Validation echouee', details: errors });
  }

  var drenaet = req.body.drenaet;
  var iepp = req.body.iepp;
  var secteur_pedagogique = req.body.secteur_pedagogique;
  var nom_ecole = req.body.nom_ecole;
  var nom_directeur = req.body.nom_directeur;
  var prenoms_directeur = req.body.prenoms_directeur;
  var contact1 = req.body.contact1;
  var contact2 = req.body.contact2;
  var email = req.body.email;
  var eleves = req.body.eleves;

  var stmt = db.prepare("INSERT INTO lots " +
    "(drenaet, iepp, secteur_pedagogique, nom_ecole, nom_directeur, prenoms_directeur, " +
    "contact1, contact2, email, eleves) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

  stmt.run([
    drenaet, iepp, secteur_pedagogique, nom_ecole,
    nom_directeur, prenoms_directeur, contact1,
    contact2 || '', email ? email.toLowerCase() : '',
    JSON.stringify(eleves)
  ], function(err) {
    if (err) {
      console.error('Erreur insertion:', err);
      logAction('INSERT_ERROR', { error: err.message }, ip);
      return res.status(500).json({ error: "Erreur lors de l'enregistrement" });
    }

    logAction('INSERT_SUCCESS', {
      id: this.lastID, ecole: nom_ecole, nb_eleves: eleves.length
    }, ip);

    res.status(201).json({
      success: true,
      id: this.lastID,
      message: eleves.length + ' eleve(s) enregistre(s) avec succes'
    });
  });

  stmt.finalize();
});

// DELETE a lot
app.delete('/api/eleves/:id', function(req, res) {
  var id = parseInt(req.params.id);
  var ip = req.ip || req.connection.remoteAddress;
  if (isNaN(id)) return res.status(400).json({ error: 'ID invalide' });

  db.run('DELETE FROM lots WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: 'Erreur de suppression' });
    if (this.changes === 0) return res.status(404).json({ error: 'Lot non trouve' });
    logAction('DELETE', { id: id }, ip);
    res.json({ success: true, message: 'Lot supprime' });
  });
});

// GET logs
app.get('/api/logs', function(req, res) {
  var limit = parseInt(req.query.limit) || 100;
  if (limit > 1000) limit = 1000;
  db.all('SELECT * FROM logs ORDER BY created_at DESC LIMIT ?', [limit], function(err, rows) {
    if (err) return res.status(500).json({ error: 'Erreur base de donnees' });
    res.json(rows);
  });
});

// ===================== KEEP-AWAKE =====================
var PING_INTERVAL = 13 * 60 * 1000;

function selfPing() {
  var url = 'http://localhost:' + PORT + '/health';
  require('http').get(url, function(res) {
    console.log('[' + new Date().toISOString() + '] Keep-alive ping OK (uptime: ' + Math.round(process.uptime()) + 's)');
  }).on('error', function(err) {
    console.error('[' + new Date().toISOString() + '] Keep-alive ping failed:', err.message);
  });
}

setTimeout(function() {
  selfPing();
  setInterval(selfPing, PING_INTERVAL);
}, 60000);

// ===================== START SERVER =====================

app.listen(PORT, function() {
  console.log(
    '\n  ======================================================\n' +
    '  |       ACESE - IEPP GRABO (Serveur Admin)          |\n' +
    '  ======================================================\n' +
    '  |  Serveur demarre sur le port ' + PORT + '                |\n' +
    '  |  Dashboard: http://localhost:' + PORT + '/admin            |\n' +
    '  |  API:       http://localhost:' + PORT + '/api/eleves       |\n' +
    '  |  Secteurs:  http://localhost:' + PORT + '/api/secteurs     |\n' +
    '  |  Health:    http://localhost:' + PORT + '/health           |\n' +
    '  ======================================================\n'
  );
});
