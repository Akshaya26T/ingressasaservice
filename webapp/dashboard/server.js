'use strict';

const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const API_URL = process.env.API_URL || 'http://api.app.localhost';
const BASE_PATH = normalizeBasePath(process.env.BASE_PATH || '/');

function normalizeBasePath(value) {
  if (!value || value === '/') {
    return '';
  }

  const normalized = value.startsWith('/') ? value : `/${value}`;
  return normalized.replace(/\/+$/, '');
}

const router = express.Router();

router.use(express.static(path.join(__dirname, 'public')));

router.get('/config.json', (_req, res) => {
  res.json({ apiUrl: API_URL, basePath: BASE_PATH || '/' });
});

router.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'app3' });
});

if (BASE_PATH) {
  app.use((req, res, next) => {
    if (req.path === BASE_PATH) {
      res.redirect(`${BASE_PATH}/`);
      return;
    }
    next();
  });
  app.use(BASE_PATH, router);
} else {
  app.use(router);
}

app.listen(PORT, () => {
  console.log(`Dashboard running on port ${PORT}`);
});
