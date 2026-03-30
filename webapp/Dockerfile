FROM node:20-alpine AS runtime

ARG APP_DIR

WORKDIR /app

COPY ${APP_DIR}/package.json ./package.json
RUN npm install --omit=dev

COPY ${APP_DIR}/ ./

USER node
CMD ["node", "server.js"]