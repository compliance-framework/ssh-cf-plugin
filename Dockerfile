# Dockerfile
# Stage 1: Build the application
FROM golang:1.22 AS builder

# Set the working directory
WORKDIR /app

# Copy the go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o plugin main.go

# Stage 2: Create a minimal image with the binary
FROM scratch
COPY --from=builder /app/plugin /compliance-framework/plugin
