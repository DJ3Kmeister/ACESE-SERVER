# 🖥️ ACESE IEPP GRABO — Serveur Admin

## Description
Serveur de réception des données élèves (API REST + Dashboard d'administration).

## Installation locale

```bash
npm install
npm run dev
```
Le serveur démarre sur `http://localhost:3000`

## API Endpoints

| Méthode | Route | Description | Auth |
|---------|-------|-------------|------|
| GET | `/api/health` | État du serveur | ❌ |
| POST | `/api/eleves` | Envoyer un lot d'élèves | ❌ |
| GET | `/api/eleves` | Lister tous les élèves | ❌ |
| GET | `/api/stats` | Statistiques globales | ❌ |
| DELETE | `/api/eleves/:id` | Supprimer un élève | ✅ |
| GET | `/admin` | Dashboard admin | ✅ |

## Authentification Admin
- Utilisateur : `admin`
- Mot de passe : défini par la variable `ADMIN_PASSWORD`

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `PORT` | `3000` | Port du serveur |
| `ADMIN_PASSWORD` | `admin2025` | Mot de passe admin |
| `ALLOWED_ORIGINS` | `*` | Origines CORS autorisées |
| `DB_FILE` | `collecte.db` | Fichier base de données SQLite |

## Déploiement sur Render

1. Créer un **Web Service** sur [render.com](https://render.com)
2. Build Command : `npm install`
3. Start Command : `npm start`
4. Variables d'environnement :
   - `ADMIN_PASSWORD` = votre mot de passe
   - `ALLOWED_ORIGINS` = URL du client (ex: `https://acese-client.onrender.com`)

---

*ACESE IEPP GRABO — DJ3Kmeister*
