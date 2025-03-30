FROM alpine:latest

# Install necessary build and runtime dependencies
RUN apk add --no-cache cmake g++ make libstdc++ libgcc boost-dev openssl-dev

# Set the working directory
WORKDIR /app

# Copy the source code and CMakeLists.txt into the container
COPY . /app

# Copy the index.html file explicitly
COPY build/index.html /app/index.html

# Debug: List the contents of the /app directory
RUN ls -l /app

# Ensure CMakeLists.txt exists before building
RUN test -f /app/CMakeLists.txt || (echo "CMakeLists.txt not found!" && exit 1)

# Build the binary
RUN cmake . && make

# Set the default command to run the server
CMD ["./http_server"]