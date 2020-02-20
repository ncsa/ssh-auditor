FROM golang:1.13

MAINTAINER Justin Azoff <jazoff@illinois.edu>

RUN mkdir /src
WORKDIR /src
COPY go.mod .
COPY go.sum .
# Get dependancies - will also be cached if we won't change mod/sum
RUN go mod download

ADD . /src/

RUN go get
RUN go build

CMD ["/bin/sh"]
