cmake_minimum_required(VERSION 3.20)
project(SocketSaveFix LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Static link so the DLL has no mingw runtime dependencies
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++ -Wl,--subsystem,windows:6.0")

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -s")
endif()

add_library(SocketSaveFix SHARED
    src/main.cpp
    src/scanner.cpp
    src/patcher.cpp
    src/hook.cpp
)

target_link_libraries(SocketSaveFix PRIVATE -lkernel32)

set_target_properties(SocketSaveFix PROPERTIES
    PREFIX ""
    OUTPUT_NAME "SocketSaveFix"
)
