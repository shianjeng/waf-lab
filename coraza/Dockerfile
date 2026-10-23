FROM caddy:2.11.7-builder AS build
RUN xcaddy build --with github.com/corazawaf/coraza-caddy/v2@v2.6.2

FROM caddy:2.11.7
COPY --from=build /usr/bin/caddy /usr/bin/caddy
