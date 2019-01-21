cmake_minimum_required(VERSION 3.13)
project(TrafficCapture)

set(CMAKE_CXX_STANDARD 14)

include_directories(TraficAnalyzer/facades)

add_executable(TrafficCapture
        TraficAnalyzer/user_facade.h
        TraficAnalyzer/main.cpp structures.h)
