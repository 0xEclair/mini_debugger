cmake_minimum_required(VERSION 3.15)
project(mini_debugger)

set(CMAKE_CXX_STANDARD 20)

include_directories(vendor/libelfin)
include_directories(vendor/linenoise)
link_directories(
        vendor/libelfin/dwarf
        vendor/libelfin/elf
)
add_executable(mini_debugger main.cc vendor/linenoise/linenoise.c)

add_executable(variable examples/variable.cc)
set_target_properties(variable PROPERTIES COMPILE_FLAGS "-gdwarf-2")

add_executable(hello examples/hello.cc)

target_link_libraries(
        mini_debugger
        dwarf++
        elf++
)
# another link method
#target_link_libraries(
#        mini_debugger
#        ${PROJECT_SOURCE_DIR}/vendor/libelfin/dwarf/libdwarf++.so
#        ${PROJECT_SOURCE_DIR}/vendor/libelfin/elf/libelf++.so
#)