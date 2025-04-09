# SPDX-License-Identifier: MIT
# Copyright (c) 2023-2025, Matthew Madison

cmake_minimum_required(VERSION 3.8)
cmake_policy(SET CMP0048 NEW)

project(keystore LANGUAGES C VERSION 0.1.0)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)

add_executable(keystoretool keystoretool.c)
target_include_directories(keystoretool PRIVATE ../ta)
target_link_libraries(keystoretool PUBLIC teec)
set_target_properties(keystoretool PROPERTIES COMPILE_WARNING_AS_ERROR ON)
target_compile_options(keystoretool PRIVATE -Wall)

add_executable(vhash-get vhash-get.c)
target_include_directories(vhash-get PRIVATE ../ta)
target_link_libraries(vhash-get PUBLIC teec)
set_target_properties(vhash-get PROPERTIES COMPILE_WARNING_AS_ERROR ON)
target_compile_options(vhash-get PRIVATE -Wall)

add_executable(vhash-store vhash-store.c)
target_include_directories(vhash-store PRIVATE ../ta)
target_link_libraries(vhash-store PUBLIC teec)
set_target_properties(vhash-store PROPERTIES COMPILE_WARNING_AS_ERROR ON)
target_compile_options(vhash-store PRIVATE -Wall)

install(TARGETS keystoretool vhash-get vhash-store RUNTIME)
