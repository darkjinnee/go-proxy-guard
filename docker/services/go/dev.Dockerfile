FROM golang:1.25-alpine

WORKDIR /var/www/app

RUN apk add --no-cache \
    bash \
    ca-certificates \
    git \
    wget

COPY go.mod go.sum ./
RUN go mod download
RUN go install github.com/air-verse/air@latest

EXPOSE 8080

CMD ["air", "-c", ".air.toml"]
