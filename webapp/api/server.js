'use strict';

const express = require('express');

const app = express();
const PORT = process.env.PORT || 4000;
const BASE_PATH = normalizeBasePath(process.env.BASE_PATH || '/');

function normalizeBasePath(value) {
  if (!value || value === '/') {
    return '';
  }

  const normalized = value.startsWith('/') ? value : `/${value}`;
  return normalized.replace(/\/+$/, '');
}

function withBasePath(pathname) {
  return `${BASE_PATH}${pathname || '/'}` || '/';
}

const router = express.Router();

app.use(express.json());

// Allow browser fetch from the frontend origin
app.use((_req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  next();
});

router.get('/', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'app2',
    endpoints: [withBasePath('/'), withBasePath('/health'), withBasePath('/api/items')],
  });
});

router.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'app2', timestamp: new Date().toISOString() });
});

router.get('/api/items', (_req, res) => {
  res.json({
    items: [
      { id: 1, name: 'Azure DevOps Agent', status: 'running' },
      { id: 2, name: 'Traefik Proxy',      status: 'running' },
      { id: 3, name: 'App1 Frontend',      status: 'running' },
      { id: 4, name: 'App2 API',           status: 'running' },
      { id: 5, name: 'App3 Dashboard',     status: 'running' },
    ],
  });
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
  console.log(`API running on port ${PORT}`);
});
