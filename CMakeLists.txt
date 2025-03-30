cmake_minimum_required(VERSION 3.10)
project(apiCpp)

set(CMAKE_CXX_STANDARD 17)

# Add Boost and OpenSSL
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

# Add the executable
add_executable(http_server src/main.cpp)

# Link libraries
target_link_libraries(http_server ${Boost_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
