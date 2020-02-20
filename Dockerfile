FROM golang:1.13

MAINTAINER Justin Azoff <jazoff@illinois.edu>

WORKDIR /go/src/github.com/ncsa/ssh-auditor
ADD . /go/src/github.com/ncsa/ssh-auditor

RUN go get
RUN go build

CMD ["/bin/sh"]
