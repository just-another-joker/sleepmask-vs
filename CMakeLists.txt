cmake_minimum_required(VERSION 3.20)

# Prevent CMake from testing the compiler with a full executable link.
# We are cross-compiling COFF object files — no linking step exists.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

project(sleepmask-vs LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# ---------------------------------------------------------------------------
# Determine target architecture from the toolchain file
# ---------------------------------------------------------------------------
if(NOT DEFINED SLEEPMASK_ARCH)
    message(FATAL_ERROR "SLEEPMASK_ARCH must be set to 'x64' or 'x86' via the toolchain file.")
endif()

# ---------------------------------------------------------------------------
# Compiler flags matching the original Makefile:
#   CFLAGS=/c /GS- /GF- /std:c++20 /clang:-fno-jump-tables
# Translated for clang targeting mingw:
#   -c                    : compile only (handled by CMake object library)
#   -fno-stack-protector  : equivalent to /GS-
#   -fno-jump-tables      : equivalent to /clang:-fno-jump-tables
#   -fms-extensions       : needed for __declspec and MSVC compatibility
# ---------------------------------------------------------------------------
set(COMMON_FLAGS
    -fno-stack-protector
    -fno-jump-tables
    -fms-extensions
)

# ---------------------------------------------------------------------------
# Include directories
# ---------------------------------------------------------------------------
set(BOF_TEMPLATE_DIR ${CMAKE_SOURCE_DIR}/bof-vs/BOF-Template)
set(SLEEPMASK_SRC_DIR ${CMAKE_SOURCE_DIR}/sleepmask-vs)

set(COMMON_INCLUDES
    ${BOF_TEMPLATE_DIR}
    ${BOF_TEMPLATE_DIR}/base
    ${SLEEPMASK_SRC_DIR}
)

# ---------------------------------------------------------------------------
# Output directories matching CNA script expectations:
#   x64: x64/Release/<name>.x64.o
#   x86: Release/<name>.x86.o
# ---------------------------------------------------------------------------
if(SLEEPMASK_ARCH STREQUAL "x64")
    set(OUTPUT_DIR ${CMAKE_SOURCE_DIR}/x64/Release)
    set(OUTPUT_EXT ".x64.o")
else()
    set(OUTPUT_DIR ${CMAKE_SOURCE_DIR}/Release)
    set(OUTPUT_EXT ".x86.o")
endif()

file(MAKE_DIRECTORY ${OUTPUT_DIR})

# ---------------------------------------------------------------------------
# Linter configuration
# ---------------------------------------------------------------------------
find_package(Python3 COMPONENTS Interpreter REQUIRED)
set(BOFLINT ${CMAKE_SOURCE_DIR}/bof-vs/BOF-Template/utils/boflint.py)

# ---------------------------------------------------------------------------
# Function: add a sleepmask .o target
#   Each .cpp is compiled directly to a COFF object file using a custom
#   command, then validated with boflint.
# ---------------------------------------------------------------------------
function(add_sleepmask_target NAME SOURCE)
    set(TARGET_NAME "${NAME}_${SLEEPMASK_ARCH}")
    set(OUTPUT_FILE "${OUTPUT_DIR}/${NAME}${OUTPUT_EXT}")
    set(SOURCE_FILE "${SLEEPMASK_SRC_DIR}/${SOURCE}")

    # Build the include flags string
    set(INCLUDE_FLAGS "")
    foreach(INC_DIR ${COMMON_INCLUDES})
        list(APPEND INCLUDE_FLAGS "-I${INC_DIR}")
    endforeach()

    # Custom command: compile source to COFF .o
    add_custom_command(
        OUTPUT ${OUTPUT_FILE}
        COMMAND ${CMAKE_CXX_COMPILER}
            -c
            --target=${CMAKE_CXX_COMPILER_TARGET}
            -std=c++20
            ${COMMON_FLAGS}
            ${INCLUDE_FLAGS}
            ${SOURCE_FILE}
            -o ${OUTPUT_FILE}
        COMMAND ${Python3_EXECUTABLE} ${BOFLINT} --loader cs ${OUTPUT_FILE}
        DEPENDS ${SOURCE_FILE}
        COMMENT "Building and linting ${NAME}${OUTPUT_EXT}"
        VERBATIM
    )

    # Custom target that depends on the output file
    add_custom_target(${TARGET_NAME} ALL DEPENDS ${OUTPUT_FILE})
endfunction()

# ---------------------------------------------------------------------------
# Sleepmask targets
# ---------------------------------------------------------------------------
add_sleepmask_target(default-sleepmask        default-sleepmask.cpp)
add_sleepmask_target(draugr-sleepmask         draugr-sleepmask.cpp)
add_sleepmask_target(indirectsyscalls-sleepmask indirectsyscalls-sleepmask.cpp)
add_sleepmask_target(retaddrspoofing-sleepmask retaddrspoofing-sleepmask.cpp)
add_sleepmask_target(threadpool-sleepmask     threadpool-sleepmask.cpp)
add_sleepmask_target(unit-test-bof            unit-test-bof.cpp)
