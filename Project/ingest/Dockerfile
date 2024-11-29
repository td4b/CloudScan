# Use the official Golang image as the build environment
FROM golang:1.23 AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
COPY go.mod go.sum ./

# Download all dependencies. They will be cached if go.mod and go.sum haven't changed
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o main .

# Use a minimal base image for the final output
FROM ubuntu:latest

# Update package list and install Python, virtualenv, and other dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    bind9-dnsutils \
    chromium-browser \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a home directory for the user and the necessary config directory
RUN mkdir -p /home/root/.config/subfinder \
             /home/root/.config/cloudscan \
             /home/root/app 

# Copy the binary from the builder image
COPY --from=builder /app/main /home/root/app/main

# Set appropriate permissions
RUN chmod +x /home/root/app/main

# Set the working directory to the root user's home directory
WORKDIR /home/root

# Command to activate the virtual environment and run the Go binary
CMD ["/home/root/app/main"]
