cmake_minimum_required(VERSION 3.15)
project(libprocman)

# C++ 20 required or else std::vector::contains throws an error because of the template implementation
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_definitions(-D_WIN32_WINNT=0x0601)
add_definitions(-DUNICODE -D_UNICODE)
    
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")

# Source files
set(SOURCES
    tests.cpp
    include/procman.cpp
)

# Include directories
include_directories(include)

# Create executable
add_executable(libprocman ${SOURCES})

# Link Windows libraries
target_link_libraries(libprocman
    advapi32
    kernel32
    ntdll
    user32
)

enable_testing()
add_test(NAME libprocman_tests COMMAND libprocman)

install(TARGETS libprocman
    RUNTIME DESTINATION bin
)