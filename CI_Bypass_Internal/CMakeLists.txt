cmake_minimum_required(VERSION 3.0.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
project(CIBypass VERSION 0.1.0 LANGUAGES C CXX)

add_library(CIBypass SHARED dllmain.cpp)