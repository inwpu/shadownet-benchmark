FROM node:22-slim
WORKDIR /app
COPY services/l3-next/ /app/
RUN npm install --no-audit --no-fund && npm run build
EXPOSE 3000
CMD ["npm", "run", "start"]
