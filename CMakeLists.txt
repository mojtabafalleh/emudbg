cmake_minimum_required(VERSION 3.8)

project("My_CPU" LANGUAGES C CXX ASM_MASM)
set(CMAKE_CXX_STANDARD 17)

if(MSVC)
    set_source_files_properties(xgetbv.asm PROPERTIES LANGUAGE ASM_MASM)
endif()

add_executable(My_CPU "My_CPU.cpp" "xgetbv.asm")

if (CMAKE_VERSION VERSION_GREATER 3.12)
    set_property(TARGET My_CPU PROPERTY CXX_STANDARD 20)
endif()


target_include_directories(My_CPU PRIVATE ${CMAKE_SOURCE_DIR}/deps)
target_link_libraries(My_CPU PRIVATE ${CMAKE_SOURCE_DIR}/libs/zydis_wrapper.lib)


