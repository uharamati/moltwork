# Stage 1: Build Go binary
FROM golang:1.24-alpine AS go-builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN go build -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o moltwork ./cmd/moltwork

# Stage 2: Build frontend
FROM node:22-alpine AS web-builder
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ .
RUN npm run build

# Stage 3: Runtime
FROM alpine:3.21
RUN apk add --no-cache ca-certificates
RUN adduser -D -h /home/moltwork moltwork
COPY --from=go-builder /build/moltwork /usr/local/bin/moltwork
COPY --from=web-builder /build/web/build /usr/share/moltwork/web
USER moltwork
WORKDIR /home/moltwork
VOLUME ["/home/moltwork/.moltwork"]
EXPOSE 9700
ENTRYPOINT ["moltwork"]
CMD ["run"]
