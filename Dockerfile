FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server
RUN go install github.com/pressly/goose/v3/cmd/goose@latest

FROM alpine:3.22 AS final
RUN apk add --no-cache ca-certificates && update-ca-certificates
WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 8080

ENTRYPOINT ["./server"]
