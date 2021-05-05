FROM golang:alpine as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN go build -o keycloak-test .
FROM alpine
RUN apk add curl
RUN adduser -S -D -H -h /app appuser
USER root
COPY --from=builder /build/keycloak-test /app/
# COPY /env/config.json /app/
WORKDIR /app
ENTRYPOINT [ "./keycloak-test" ]
