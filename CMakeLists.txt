cmake_minimum_required(VERSION 3.15)
project(mini_debugger)

set(CMAKE_CXX_STANDARD 20)

add_executable(mini_debugger main.cc vendor/linenoise/linenoise.c)
add_executable(variable examples/variable.cc)
add_executable(hello examples/hello.cc)