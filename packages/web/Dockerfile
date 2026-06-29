# Self-host the Preflight dashboard. Build from the repo root:
#   docker build -f packages/web/Dockerfile -t preflight-web .
#   docker run -p 3000:3000 preflight-web
# Uses Next's standalone output, so the runtime image carries only the traced deps.

FROM node:22-alpine AS build
WORKDIR /app
COPY . .
RUN npm ci
RUN npm run build -w @preflight/web

FROM node:22-alpine AS run
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
# standalone bundle (server.js + traced node_modules) + the static assets it serves
COPY --from=build /app/packages/web/.next/standalone ./
COPY --from=build /app/packages/web/.next/static ./packages/web/.next/static
EXPOSE 3000
CMD ["node", "packages/web/server.js"]
