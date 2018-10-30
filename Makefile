all: build test
build:
	go get -t -v ./...
	go build
test:
	go test -v -short ./...
e2e-test:
	docker-compose run --rm auditor go test -v ./... || (docker logs sshauditor_alpine-sshd-test-key_1 ; false )
static:
	go get -t -v ./...
	go build --ldflags '-extldflags "-static"'

.PHONY: rpm
rpm:
	goreleaser --skip-publish
