cmake_minimum_required(VERSION 3.8)

project("My_CPU" LANGUAGES C CXX ASM_MASM)
set(CMAKE_CXX_STANDARD 17)

# Check MSVC for ASM
if(MSVC)
    set_source_files_properties(xgetbv.asm PROPERTIES LANGUAGE ASM_MASM)
endif()

# Create the main executable
add_executable(My_CPU "My_CPU.cpp" "asm_function.asm")

# Optional: Use C++20 if available
if (CMAKE_VERSION VERSION_GREATER 3.12)
    set_property(TARGET My_CPU PROPERTY CXX_STANDARD 20)
endif()

# Add unicorn subdirectory
#add_subdirectory(deps/unicorn)

# Debug: check if target 'unicorn' exists
#if (TARGET unicorn)
 #   target_link_libraries(My_CPU PRIVATE unicorn)
#endif()

# Link with your local static lib
target_link_libraries(My_CPU PRIVATE ${CMAKE_SOURCE_DIR}/libs/zydis_wrapper.lib)
