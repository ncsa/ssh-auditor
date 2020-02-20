all: build test
build:
	go get -t -v ./...
	go build
test:
	go test -v -short ./...
e2e-test:
	docker-compose up --abort-on-container-exit --build
static:
	go get -t -v ./...
	go build --ldflags '-extldflags "-static"'

.PHONY: rpm
rpm:
	goreleaser --skip-publish
