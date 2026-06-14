cmake_minimum_required(VERSION 3.16)

project(pgs_admin_web LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Network HttpServer)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Network HttpServer)

if (QT_VERSION_MAJOR EQUAL 6)
    qt_add_executable(pgs_admin_web
        src/main.cpp
        src/WebServer.h
        src/WebServer.cpp
    )
else()
    add_executable(pgs_admin_web
        src/main.cpp
        src/WebServer.h
        src/WebServer.cpp
    )
endif()

target_link_libraries(pgs_admin_web PRIVATE
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Network
    Qt${QT_VERSION_MAJOR}::HttpServer
)
