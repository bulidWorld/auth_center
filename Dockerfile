FROM node:24-alpine

RUN apk add --no-cache nginx python3 make g++ gcc

WORKDIR /opt/apps/auth_center

COPY package*.json ./
RUN npm ci --production

COPY . .

RUN npm rebuild better-sqlite3

RUN mkdir -p /var/log/app-auth-center data \
  && rm -f /etc/nginx/http.d/default.conf

COPY nginx/auth-center.conf /etc/nginx/http.d/auth-center.conf

EXPOSE 10532

CMD ["sh", "-c", "nginx -g 'daemon off;' & exec node src/index.js"]
