# SPDX-License-Identifier: MIT
# Copyright (c) 2023, Matthew Madison

cmake_minimum_required(VERSION 3.8)
cmake_policy(SET CMP0048 NEW)

project(keystore LANGUAGES C VERSION 0.0.0)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)

add_executable(keystoretool keystoretool.c)
target_include_directories(keystoretool PRIVATE ../ta)
target_link_libraries(keystoretool PUBLIC teec)
set_target_properties(keystoretool PROPERTIES COMPILE_WARNING_AS_ERROR ON)
target_compile_options(keystoretool PRIVATE -Wall)

install(TARGETS keystoretool RUNTIME)
