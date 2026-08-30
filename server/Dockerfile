FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o server .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/server .
COPY db/schema.sql ./db/schema.sql
EXPOSE 8080
CMD ["./server"]