cmake_minimum_required(VERSION 3.0.0)
project(MHCI_Bypass VERSION 0.1.0 LANGUAGES C CXX)

if(MSVC)
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
endif()

add_executable(MHCI_Bypass main.cpp)