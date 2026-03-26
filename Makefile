BINARY := vercelsior
VERSION := 1.0.0
LDFLAGS := -s -w

.PHONY: build clean test all

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/vercelsior/

all: clean
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 ./cmd/vercelsior/
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 ./cmd/vercelsior/
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64 ./cmd/vercelsior/
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 ./cmd/vercelsior/
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe ./cmd/vercelsior/

test:
	go test ./...

clean:
	rm -rf dist/ $(BINARY) $(BINARY).exe
