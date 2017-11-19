FROM golang:1.9

MAINTAINER Justin Azoff <jazoff@illinois.edu>

WORKDIR /go/src/github.com/ncsa/ssh-auditor
ADD . /go/src/github.com/ncsa/ssh-auditor

RUN go get
RUN go build

CMD ["/bin/sh"]
