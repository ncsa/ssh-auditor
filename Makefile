all: build test
build:
	go get -t -v ./...
	go build
test:
	go test -v ./...
static:
	go get -t -v ./...
	go build --ldflags '-extldflags "-static"'

.PHONY: rpm
rpm: build
rpm: VERSION=0.3
rpm:
	fpm -f -s dir -t rpm -n ssh-auditor -v $(VERSION) \
	--iteration=1 \
	--architecture native \
	--description "SSH Auditor" \
	./ssh-auditor=/usr/bin/
