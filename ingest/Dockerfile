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
FROM alpine:latest

# Create a non-root user and group
RUN addgroup -S cloudscan && adduser -S cloudscan -G cloudscan

# Create a home directory for the user and the necessary config directory
RUN mkdir -p /home/cloudscan/.config/subfinder
RUN mkdir -p /home/cloudscan/app

# Set ownership of the home directory
RUN chown -R cloudscan:cloudscan /home/cloudscan

# Copy the binary from the builder image
COPY --from=builder /app/main /home/cloudscan/app/main

RUN chmod +x /home/cloudscan/app/main

RUN chown cloudscan:cloudscan /home/cloudscan/app/main

# Switch to the non-root user
USER cloudscan

# Set the working directory to the non-root user's home directory
WORKDIR /home/cloudscan

# Command to run the executable
CMD ["/home/cloudscan/app/main"]
