cmake_minimum_required(VERSION 3.1)
project(RADIO C)

set(CMAKE_C_STANDARD 23)

set(PROJECT_HEADERS
        err.h)

add_executable(sikradio-sender sikradio-sender.c sender_utility.h ${PROJECT_HEADERS})
add_executable(sikradio-receiver sikradio-receiver.c ${PROJECT_HEADERS})
