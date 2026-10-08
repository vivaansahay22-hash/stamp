FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
COPY apps/api/package.json ./apps/api/package.json
COPY apps/web/package.json ./apps/web/package.json
COPY packages/sdk/package.json ./packages/sdk/package.json
COPY prisma ./prisma
RUN npm install
COPY . .
RUN npm run build
EXPOSE 3001
CMD ["npm", "run", "start", "--workspace", "apps/api"]
