cmake_minimum_required(VERSION 3.16)

project(pgs_cluster_web LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Network HttpServer)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Network HttpServer)

set(PGS_CLUSTER_SOURCES
    src/main.cpp
    src/ClusterServer.h
    src/ClusterServer.cpp
)

if (QT_VERSION_MAJOR EQUAL 6)
    qt_add_executable(pgs_cluster_web ${PGS_CLUSTER_SOURCES})
else()
    add_executable(pgs_cluster_web ${PGS_CLUSTER_SOURCES})
endif()

target_include_directories(pgs_cluster_web PRIVATE ../../include)
target_link_libraries(pgs_cluster_web PRIVATE
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Network
    Qt${QT_VERSION_MAJOR}::HttpServer
    ws2_32
)
