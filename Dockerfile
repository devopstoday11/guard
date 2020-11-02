# build stage
FROM golang:alpine3.12 AS build-env
RUN mkdir -p /go/src/github.com/pipo02mix/grumpy
WORKDIR /go/src/github.com/pipo02mix/grumpy
COPY  . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o guard

FROM alpine:3.12.1
COPY --from=build-env /go/src/github.com/pipo02mix/grumpy/guard .
COPY --from=build-env /etc/passwd /etc/passwd
ENTRYPOINT ["/guard"]
