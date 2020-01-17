# ビルド環境
FROM node:10.13-alpine as build-stage

COPY . /app/

WORKDIR /app

RUN  npm install && npm run build

# 本番環境
FROM node:latest as production-stage

WORKDIR /app

COPY  --from=build-stage ./app/dist ./dist

COPY  --from=build-stage ./app/src ./src

COPY package* ./

RUN  npm install --production

CMD ["sh", "-c", "npm start"]

