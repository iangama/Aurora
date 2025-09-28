FROM node:20-bookworm-slim
WORKDIR /app

# deps do sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
  openssl ca-certificates wget curl && \
  rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev

# copie o schema e GERE o client AQUI
COPY prisma ./prisma
RUN npx prisma generate

# app
COPY server.js ./

EXPOSE 4000
CMD ["npm", "start"]
