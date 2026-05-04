cmake_minimum_required(VERSION 3.22.1)

project(mlkemnative LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(MLKEM_NATIVE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mlkem-native/mlkem")

add_library(
    mlkemnative
    SHARED
    mlkem_native_android.c
    "${MLKEM_NATIVE_DIR}/mlkem_native.c"
)

target_include_directories(
    mlkemnative
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${MLKEM_NATIVE_DIR}"
)

target_compile_definitions(
    mlkemnative
    PRIVATE
    MLK_CONFIG_PARAMETER_SET=768
    MLK_CONFIG_NO_RANDOMIZED_API
)

target_compile_options(
    mlkemnative
    PRIVATE
    -Wall
    -Wextra
)

find_library(log-lib log)
target_link_libraries(mlkemnative PRIVATE ${log-lib})
