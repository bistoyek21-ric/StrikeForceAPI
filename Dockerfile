# Use Ubuntu 20.04 as base image
FROM ubuntu:20.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    g++ \
    libssl-dev \
    libasio-dev \
    unzip \
    zip \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy server code and Crow header
COPY server.cpp .
COPY crow_all.h .

# Compile the server
RUN g++ server.cpp -o server -lcrypto -lssl -std=c++17

# Expose port 8080
EXPOSE 8080

# Run the server
CMD ["./server"]