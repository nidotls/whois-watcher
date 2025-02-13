# Stage 1: Modules caching
FROM golang:1.24 as modules
COPY go.mod go.sum /modules/
WORKDIR /modules
RUN go mod download

# Stage 2: Build
FROM golang:1.24 as builder
COPY --from=modules /go/pkg /go/pkg
COPY . /workdir
WORKDIR /workdir

# Build your app
RUN GOOS=linux GOARCH=amd64 go build -o /bin/whois-watcher

# Stage 3: Final
FROM ubuntu:jammy
COPY --from=builder /bin/whois-watcher /
RUN apt-get update && apt-get install -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

CMD ["/whois-watcher"]
