cmake_minimum_required(VERSION 3.12)
project(TraficAnalyzer)

set(CMAKE_CXX_STANDARD 14)
set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost 1.45.0 COMPONENTS regex)

if (Boost_FOUND)
    find_library(TINS_LIBRARY tins)

    add_executable(TraficAnalyzer main.cpp traffic_capture_helper.h http_handler.h)
    target_link_libraries(TraficAnalyzer "${TINS_LIBRARY}")
    target_link_libraries(TraficAnalyzer "${TINS_LIBRARY}")

    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(TraficAnalyzer ${Boost_LIBRARIES})
endif ()