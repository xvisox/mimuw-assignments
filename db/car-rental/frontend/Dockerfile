# syntax=docker/dockerfile:1

FROM node:18-alpine

WORKDIR /app

COPY ["package.json", "package-lock.json*", "./"]

RUN npm install
RUN npm install -g @angular/cli@latest

COPY . .

CMD ng serve --host 0.0.0.0
