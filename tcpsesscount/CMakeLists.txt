cmake_minimum_required(VERSION 3.5)

project(tcpsesscount LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(HEADERS finite_state_machine.h tcp_dump_parser.h)
set(SOURCES main.cpp tcp_dump_parser.cpp)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})
target_link_libraries(${PROJECT_NAME} pcap)
