all: build test
build:
	go get -t -v ./...
	go build
test:
	go test -v -short ./...
e2e-test:
	docker-compose run --rm auditor go test -v ./...
static:
	go get -t -v ./...
	go build --ldflags '-extldflags "-static"'

.PHONY: rpm
rpm: static
rpm: VERSION=$(shell ./ssh-auditor version)
rpm:
	fpm -f -s dir -t rpm -n ssh-auditor -v $(VERSION) \
	--iteration=1 \
	--architecture native \
	--description "SSH Auditor" \
	./ssh-auditor=/usr/bin/
