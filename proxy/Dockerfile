FROM node:22-alpine

WORKDIR /app
COPY proxy/security.mjs proxy/server.mjs ./

EXPOSE 4000
CMD ["node", "server.mjs"]
