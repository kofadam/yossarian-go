FROM golang:1.21-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go module files first (for better layer caching)
COPY go.mod go.sum* ./

# Download dependencies (air-gap: this layer is cached unless go.mod changes)
RUN go mod download

# Copy source code and templates
COPY *.go ./
COPY templates/ ./templates/

# Build the application
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o yossarian-go .

# Final stage - minimal runtime image
FROM alpine:latest

# Install ca-certificates and wget for health checks
RUN apk --no-cache add ca-certificates wget

# Set working directory
WORKDIR /app

# Copy binary and templates from builder stage
COPY --from=builder /app/yossarian-go .
COPY --from=builder /app/templates/ ./templates/

# Expose port
EXPOSE 8080

# Run the application
CMD ["./yossarian-go"]