cmake_minimum_required(VERSION 3.16)

project(pgs_admin_web LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.8 REQUIRED COMPONENTS Core Network HttpServer)

qt_add_executable(pgs_admin_web
    src/main.cpp
    src/WebServer.h
    src/WebServer.cpp
    ../common/SimpleHttp.h
    ../common/SimpleHttp.cpp
    ../../src/common/PGSClient.cpp
)

target_include_directories(pgs_admin_web PRIVATE ../../include)
target_link_libraries(pgs_admin_web PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::HttpServer
    ws2_32
)
