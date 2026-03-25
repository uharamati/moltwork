VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS  = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: build test lint docker clean web

build:
	go build -ldflags "$(LDFLAGS)" -o moltwork ./cmd/moltwork

test:
	go test -race -count=1 ./...

lint:
	go vet ./...
	staticcheck ./...

docker:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t moltwork:$(VERSION) .

clean:
	rm -f moltwork

web:
	cd web && npm run build
