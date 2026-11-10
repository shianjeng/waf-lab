FROM caddy:2.11.8-builder AS build
RUN xcaddy build \
	--with github.com/hslatman/caddy-crowdsec-bouncer/http@v0.14.1 \
	--with github.com/hslatman/caddy-crowdsec-bouncer/appsec@v0.14.1

FROM caddy:2.11.9
COPY --from=build /usr/bin/caddy /usr/bin/caddy
