'use strict';

const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const API_URL = process.env.API_URL || 'http://api.app.localhost';
const APP_VERSION = process.env.APP_VERSION || 'unknown';
const APP_RELEASE = process.env.APP_RELEASE || 'v1';
const FEATURE_BANNER = (process.env.FEATURE_BANNER || 'false').toLowerCase() === 'true';
const BASE_PATH = normalizeBasePath(process.env.BASE_PATH || '/');

function normalizeBasePath(value) {
  if (!value || value === '/') {
    return '';
  }

  const normalized = value.startsWith('/') ? value : `/${value}`;
  return normalized.replace(/\/+$/, '');
}

const router = express.Router();

app.use((_req, res, next) => {
  res.set('X-App-Version', APP_VERSION);
  next();
});

router.use(express.static(path.join(__dirname, 'public')));

router.get('/config.json', (_req, res) => {
  res.json({
    apiUrl: API_URL,
    appVersion: APP_VERSION,
    appRelease: APP_RELEASE,
    featureBanner: FEATURE_BANNER,
    basePath: BASE_PATH || '/',
  });
});

router.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'app1',
    version: APP_VERSION,
    release: APP_RELEASE,
    featureBanner: FEATURE_BANNER,
  });
});

router.get('/version', (_req, res) => {
  res.json({ version: APP_VERSION, release: APP_RELEASE });
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
  console.log(`Frontend running on port ${PORT}`);
});
