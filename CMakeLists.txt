cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(libssl-keylog LANGUAGES C)

include("${VITASDK}/share/vita.cmake" REQUIRED)

set(COMPILER_FLAGS "-g -Wall -Os -ffunction-sections -fdata-sections -fvisibility=hidden -fno-builtin-printf")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMPILER_FLAGS} -std=gnu11")

add_executable(libssl-keylog
    src/main.c
    src/common.c
    src/cfg.c
)

target_link_libraries(libssl-keylog PRIVATE
    SceLibKernel_stub
    SceIofilemgr_stub
    SceSysmodule_stub
    SceNet_stub_weak
    stai_stub
)

target_link_options(libssl-keylog PRIVATE
    -nostdlib
    --entry=module_start
)

vita_create_self(libssl-keylog.suprx libssl-keylog
    STRIPPED
    REL_OPTIMIZE
)
