cmake_minimum_required(VERSION 3.12)
project(TraficAnalyzer)

set(CMAKE_CXX_STANDARD 14)
include(FindPCAP.cmake)

add_executable(TraficAnalyzer main.cpp facades/user_facade.h)
target_link_libraries(TraficAnalyzer ${PCAP_LIBRARY})