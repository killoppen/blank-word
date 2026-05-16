FROM node:20-alpine

WORKDIR /app

COPY package.json .
RUN npm install

COPY . .

VOLUME ["/app/data"]
ENV PORT=3001
ENV DATA_DIR=/app/data

EXPOSE 3001

CMD ["node", "server.js"]
