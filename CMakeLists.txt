cmake_minimum_required(VERSION 3.1)
project(SIKRadio)

set(CMAKE_CXX_STANDARD 20)

find_package(Boost COMPONENTS REQUIRED program_options log)
include_directories(${Boost_INCLUDE_DIRS})

file(GLOB PROJECT_HEADERS "utils/*.h")
# Sender executable file.
file(GLOB SENDER_SRC "sender/*.hpp")
file(GLOB SENDER_MAIN "sikradio-sender.cpp")
add_executable(sikradio-sender ${SENDER_MAIN} ${SENDER_SRC} ${PROJECT_HEADERS})
target_link_libraries(sikradio-sender ${Boost_LIBRARIES})
# Receiver executable file.
file(GLOB RECEIVER_SRC "receiver/*.hpp")
file(GLOB RECEIVER_MAIN "sikradio-receiver.cpp")
add_executable(sikradio-receiver ${RECEIVER_MAIN} ${RECEIVER_SRC} ${PROJECT_HEADERS})
target_link_libraries(sikradio-receiver ${Boost_LIBRARIES})
