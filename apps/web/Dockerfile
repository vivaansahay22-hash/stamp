FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
COPY apps/web/package.json ./apps/web/package.json
COPY apps/api/package.json ./apps/api/package.json
COPY packages/sdk/package.json ./packages/sdk/package.json
RUN npm install
COPY . .
RUN npm run build --workspace apps/web
EXPOSE 5173
CMD ["npm", "run", "dev", "--workspace", "apps/web"]
