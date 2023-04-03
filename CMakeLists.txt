cmake_minimum_required(VERSION 3.1)
project(SIKRadio)

set(CMAKE_CXX_STANDARD 20)
set(PROJECT_HEADERS utils/err.h utils/const.h utils/types.h utils/common.h)

find_package(Boost COMPONENTS REQUIRED program_options log)
include_directories(${Boost_INCLUDE_DIRS})

# Sender executable file.
file(GLOB SENDER_SRC "sender/*.h" "sender/*.cpp")
file(GLOB SENDER_MAIN "sikradio-sender.cpp")
add_executable(sikradio-sender ${SENDER_MAIN} ${SENDER_SRC} ${PROJECT_HEADERS})
target_link_libraries(sikradio-sender ${Boost_LIBRARIES})
# Receiver executable file.
file(GLOB RECEIVER_SRC "receiver/*.h" "receiver/*.cpp")
file(GLOB RECEIVER_MAIN "sikradio-receiver.cpp")
add_executable(sikradio-receiver ${RECEIVER_MAIN} ${RECEIVER_SRC} ${PROJECT_HEADERS})
