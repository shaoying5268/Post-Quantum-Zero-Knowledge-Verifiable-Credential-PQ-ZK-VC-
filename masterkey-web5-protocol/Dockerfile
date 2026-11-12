FROM node:22-slim

WORKDIR /app
COPY package*.json ./
COPY packages/pq-zkkyc-sdk/package.json ./packages/pq-zkkyc-sdk/
COPY packages/web5-dwn-vault/package.json ./packages/web5-dwn-vault/
COPY packages/judicial-escrow/package.json ./packages/judicial-escrow/
COPY packages/trust-gateway/package.json ./packages/trust-gateway/

RUN npm ci --omit=dev || npm install

COPY . .
RUN npm run build

EXPOSE 4000
ENV NODE_ENV=production
CMD ["npm", "--workspace=@masterkey/trust-gateway", "run", "start"]
