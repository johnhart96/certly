FROM node:24-alpine

LABEL org.opencontainers.image.source="https://github.com/johnhart/certly" \
      org.opencontainers.image.description="A web-based local certificate authority" \
      org.opencontainers.image.licenses="MIT"

ENV NODE_ENV=production \
    PORT=3000 \
    DATA_DIR=/data

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY src ./src
COPY public ./public

RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=30s \
  CMD wget -qO- http://127.0.0.1:3000/api/ca > /dev/null || exit 1

CMD ["node", "src/server.js"]
