cmake_minimum_required(VERSION 3.16.3)
project(JNP1_3)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -O2")

include_directories(.)

add_executable(JNP1_3
        moneybag.h
        moneybag_example.cc)
