.PHONY: all build-webapi build-pullworker build-scanworker

all: build-webapi build-pullworker build-scanworker

build-webapi:
	go build -o ./bin/webapi ./cmd/webapi

build-pullworker:
	go build -o ./bin/pull_worker ./cmd/pullworker

build-scanworker:
	go build -o ./bin/scan_worker ./cmd/scanworker


