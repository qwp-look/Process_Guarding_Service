cmake_minimum_required(VERSION 3.16)

project(pgs_admin_qt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

if (QT_VERSION_MAJOR EQUAL 6)
    qt_add_executable(pgs_admin_qt
        src/main.cpp
        src/MainWindow.h
        src/MainWindow.cpp
    )
else()
    add_executable(pgs_admin_qt
        src/main.cpp
        src/MainWindow.h
        src/MainWindow.cpp
    )
endif()

target_link_libraries(pgs_admin_qt PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)
