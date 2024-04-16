cmake_minimum_required(VERSION 3.28)

if (NOT DEFINED CMAKE_ANDROID_NDK)
    set(CMAKE_ANDROID_NDK D:/Android/SDK/ndk/26.1.10909125)
    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_ANDROID_NDK}/build/cmake/android.toolchain.cmake)
    set(CMAKE_SYSTEM_NAME Android)
    set(CMAKE_SYSTEM_VERSION 24)
    set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    set(ANDROID_ABI arm64-v8a)
    set(ANDROID_PLATFORM android-26)
    set(ANDROID_NDK ${CMAKE_ANDROID_NDK})
else ()
    SET(ANDROID_STUDIO_BUILD true)
endif ()

project(AndroidJNICreateJavaVM)

set(CMAKE_CXX_STANDARD 20)


include(FetchContent)


macro(SET_OPTION option value)
    set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()
SET_OPTION(DOBBY_DEBUG OFF)
SET_OPTION(DOBBY_GENERATE_SHARED OFF)

FetchContent_Declare(
        Dobby
        GIT_REPOSITORY https://github.com/jmpews/Dobby.git
        GIT_TAG b0176de
)
FetchContent_MakeAvailable(Dobby)

add_executable(AndroidJNICreateJavaVM main.cpp)

target_link_libraries(AndroidJNICreateJavaVM dobby_static log android)