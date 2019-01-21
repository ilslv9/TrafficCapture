cmake_minimum_required(VERSION 3.12)
project(TraficAnalyzer)

set(CMAKE_CXX_STANDARD 14)

find_library(TINS_LIBRARY tins)

add_executable(TraficAnalyzer main.cpp user_facade.h)
target_link_libraries(TraficAnalyzer "${TINS_LIBRARY}")