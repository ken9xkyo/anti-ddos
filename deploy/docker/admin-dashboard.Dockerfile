# syntax=docker/dockerfile:1.7

ARG NODE_IMAGE=node:22.22.1-alpine3.22
ARG NGINX_IMAGE=nginx:1.30.1-alpine3.23

FROM ${NODE_IMAGE} AS build
WORKDIR /app

COPY web/dashboard/package.json web/dashboard/package-lock.json ./
RUN npm ci

COPY web/dashboard ./
RUN npm run build

FROM ${NGINX_IMAGE}

COPY deploy/docker/admin-dashboard.nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chown=nginx:nginx /app/dist /usr/share/nginx/html

RUN mkdir -p /var/cache/nginx /var/run \
    && chown -R nginx:nginx /var/cache/nginx /var/run /usr/share/nginx/html /etc/nginx/conf.d

USER nginx
EXPOSE 8080
