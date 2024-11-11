# Use the official Golang image as the build environment
FROM golang:1.20 AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
COPY go.mod go.sum ./

# Download all dependencies. They will be cached if go.mod and go.sum haven't changed
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go app
RUN go build -o main .

# Use a minimal base image for the final output
FROM alpine:latest

# Set the working directory in the new image
WORKDIR /app

# Copy the binary from the builder image
COPY --from=builder /app/main .

# Command to run the executable
CMD ["./main"]
