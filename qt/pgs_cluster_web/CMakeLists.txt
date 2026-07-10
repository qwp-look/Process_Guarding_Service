cmake_minimum_required(VERSION 3.16)

project(pgs_cluster_web LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.8 REQUIRED COMPONENTS Core Network HttpServer)

set(PGS_CLUSTER_SOURCES
    src/main.cpp
    src/ClusterServer.h
    src/ClusterServer.cpp
)

qt_add_executable(pgs_cluster_web ${PGS_CLUSTER_SOURCES})

target_include_directories(pgs_cluster_web PRIVATE ../../include)
target_link_libraries(pgs_cluster_web PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::HttpServer
    ws2_32
)
