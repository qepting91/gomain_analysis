FROM golang:1.22 as build
WORKDIR /app
# Copy dependencies list
COPY go.mod go.sum ./
# COPY internal internal/
# COPY pkg pkg/
COPY main.go main.go
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o main main.go
# Copy artifacts to a clean image
FROM alpine:3.20
WORKDIR /app
COPY --from=build /app/main /app/main
CMD [ "/app/main" ]