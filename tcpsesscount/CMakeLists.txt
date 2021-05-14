cmake_minimum_required(VERSION 3.5)

project(tcpsesscount LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(HEADERS finite_state_machine.h tcp_dump_parser.h tcp_dump_parser_helper.h)
set(SOURCES main.cpp tcp_dump_parser.cpp tcp_dump_parser_helper.cpp)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})
target_link_libraries(${PROJECT_NAME} pcap)
