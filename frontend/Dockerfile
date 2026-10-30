# AEGIS frontend image: build the static site, serve it with nginx.
# NOTE: written for the 1.0 release but NOT built or run on the development
# machine (Docker was unavailable there). See README "Docker".

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-fund --no-audit
COPY . .
RUN npm run build

FROM nginx:1.27-alpine AS runtime
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
