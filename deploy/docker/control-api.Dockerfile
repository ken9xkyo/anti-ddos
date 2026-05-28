# syntax=docker/dockerfile:1.7

ARG GO_IMAGE=golang:1.22.12-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${GO_IMAGE} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/control-api ./cmd/control-api \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/control-admin ./cmd/control-admin

FROM ${RUNTIME_IMAGE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin anti-ddos

COPY --from=build /out/control-api /usr/local/bin/control-api
COPY --from=build /out/control-admin /usr/local/bin/control-admin

USER 10001:10001
EXPOSE 8080

ENTRYPOINT ["control-api"]
CMD ["serve"]
