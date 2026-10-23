FROM caddy:2.11.7-builder AS build
RUN xcaddy build \
	--with github.com/hslatman/caddy-crowdsec-bouncer/http@v0.14.1 \
	--with github.com/hslatman/caddy-crowdsec-bouncer/appsec@v0.14.1

FROM caddy:2.11.7
COPY --from=build /usr/bin/caddy /usr/bin/caddy
