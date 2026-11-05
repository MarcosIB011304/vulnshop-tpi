# Imagen base con herramientas de build para compilar better-sqlite3.
FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .

# El puerto y el modo se pasan por variables de entorno desde docker-compose.
EXPOSE 8080
CMD ["node", "src/app.js"]
