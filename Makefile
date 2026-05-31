BINARY := vercelsior
# Local/dev version. Real releases are versioned from the git tag by
# goreleaser (-X main.version={{.Version}}); this value is only used for
# `make build` / `make all` outside a release.
VERSION := 1.0.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build clean test test-race lint docker all

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/vercelsior/

test:
	go test ./... -count=1

# Race detector requires cgo + a C toolchain (CGO_ENABLED=1).
test-race:
	CGO_ENABLED=1 go test ./... -race -count=1

lint:
	golangci-lint run ./...

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY):$(VERSION) .

all: clean
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 ./cmd/vercelsior/
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 ./cmd/vercelsior/
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64 ./cmd/vercelsior/
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 ./cmd/vercelsior/
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe ./cmd/vercelsior/

clean:
	rm -rf dist/ $(BINARY) $(BINARY).exe
