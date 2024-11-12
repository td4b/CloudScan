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
    python3-venv \
    bind9-dnsutils \
    chromium-browser \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and group
RUN groupadd -r cloudscan && useradd -r -g cloudscan cloudscan

# Create a home directory for the user and the necessary config directory
RUN mkdir -p /home/cloudscan/.config/subfinder \
             /home/cloudscan/.config/cloudscan \
             /home/cloudscan/app \
             /home/cloudscan/venv

# Set ownership of the home directory
RUN chown -R cloudscan:cloudscan /home/cloudscan

# Copy the binary from the builder image
COPY --from=builder /app/main /home/cloudscan/app/main

# Set appropriate permissions
RUN chmod +x /home/cloudscan/app/main
RUN chown cloudscan:cloudscan /home/cloudscan/app/main

# Switch to the non-root user
USER cloudscan

# Set the working directory to the non-root user's home directory
WORKDIR /home/cloudscan

# Create and activate the Python virtual environment
RUN python3 -m venv /home/cloudscan/.venv
ENV PATH="/home/cloudscan/.venv/bin:$PATH"

# Command to activate the virtual environment and run the Go binary
CMD ["/bin/sh", "-c", ". /home/cloudscan/.venv/bin/activate && /home/cloudscan/app/main"]
