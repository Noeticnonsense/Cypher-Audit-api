FROM debian:bookworm-slim AS john-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential pkg-config libssl-dev zlib1g-dev libbz2-dev libgmp-dev libpcap-dev \
    libopenmpi-dev openmpi-bin ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch bleeding-jumbo https://github.com/openwall/john.git
WORKDIR /src/john/src
RUN ./configure --disable-native-tests && make -s clean && make -sj2

FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    hashcat ca-certificates tini libssl3 zlib1g libbz2-1.0 libgmp10 libpcap0.8 openmpi-bin \
    && rm -rf /var/lib/apt/lists/*
COPY --from=john-builder /src/john/run /opt/john/run
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY server.js ./
RUN mkdir -p /tmp/cipher-audit/uploads && chown -R node:node /app /tmp/cipher-audit /opt/john/run
USER node
ENV NODE_ENV=production \
    JOHN_PATH=/opt/john/run/john \
    ZIP2JOHN_PATH=/opt/john/run/zip2john
EXPOSE 10000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["npm", "start"]
