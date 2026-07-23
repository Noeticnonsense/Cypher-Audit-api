FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends hashcat john ca-certificates tini && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY server.js ./
RUN mkdir -p /tmp/cipher-audit && chown -R node:node /app /tmp/cipher-audit
USER node
ENV NODE_ENV=production
EXPOSE 10000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["npm", "start"]
