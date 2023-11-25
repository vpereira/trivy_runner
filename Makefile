.PHONY: all build-webapi build-pullworker build-scanworker

all: build-webapi build-pullworker build-scanworker

build-webapi:
	go build -o ./bin/webapi ./cmd/webapi

build-pullworker:
	go build -o ./bin/pull_worker ./cmd/pullworker

build-scanworker:
	go build -o ./bin/scan_worker ./cmd/scanworker

lint:
	docker run --rm -v "$(CURDIR):/app" -w /app golangci/golangci-lint:v1.55.2 golangci-lint run -v


