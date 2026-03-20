FROM golang:1.23 AS build
WORKDIR /app

# Copy dependency manifests first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY cmd/ cmd/
COPY internal/ internal/
COPY queries/ queries/

# Build the binary
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gomain_analysis ./cmd/

# Runtime image
FROM alpine:3.20
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=build /app/gomain_analysis /app/gomain_analysis
COPY --from=build /app/queries/ /app/queries/
CMD ["/app/gomain_analysis"]