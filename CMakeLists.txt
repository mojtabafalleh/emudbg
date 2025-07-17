cmake_minimum_required(VERSION 3.8)

project(emudbg LANGUAGES C CXX ASM_MASM)
set(CMAKE_CXX_STANDARD 17)

# Check MSVC for ASM
if(MSVC)
    set_source_files_properties(xgetbv.asm PROPERTIES LANGUAGE ASM_MASM)
endif()

# Create the main executable
add_executable(emudbg "emudbg.cpp" "asm_function.asm")

# Optional: Use C++20 if available
if (CMAKE_VERSION VERSION_GREATER 3.12)
    set_property(TARGET emudbg PROPERTY CXX_STANDARD 20)
endif()

# Link with your local static lib
target_link_libraries(emudbg PRIVATE ${CMAKE_SOURCE_DIR}/libs/zydis_wrapper.lib)
