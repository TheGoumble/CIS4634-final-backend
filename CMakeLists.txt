cmake_minimum_required(VERSION 3.30)

# The toolchain file setup should ideally be in a CMakePresets.json file,
# but we'll keep it here for simplicity
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "Vcpkg toolchain file")

project(ProjectBackend VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add dependencies
#find_package( CONFIG REQUIRED)
find_package(websocketpp CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# No C++20 modules
set(CMAKE_CXX_SCAN_FOR_MODULES OFF) 

# ProjectBackend executable
add_executable(ProjectBackend)
add_executable(MyWebSocketApp main.cpp)

# ProjectBackend sources and headers
file(GLOB_RECURSE ProjectBackend_SOURCES CONFIGURE_DEPENDS 
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.inl"
)

target_sources(ProjectBackend PRIVATE ${ProjectBackend_SOURCES})

# ProjectBackend include dirs
target_include_directories(ProjectBackend PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Preprocessor defines
target_compile_definitions(ProjectBackend PRIVATE
    MY_TEST_DEFINE
)

# Automatically links to these libs
target_link_libraries(ProjectBackend PRIVATE
    MyWebSocketApp websocketpp::websocketpp
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Add directories with any random loose .dlls or .libs here
target_link_directories(ProjectBackend PRIVATE
  
)

# Set configuration properties for ProjectBackend
if(MSVC)
    target_compile_options(ProjectBackend PRIVATE
        /W3
        /MP # multithreaded build
        /WX # warnings as errors
        /ZI # program database for edit and continue
    )
else()
    target_compile_options(ProjectBackend PRIVATE 
        -Wall 
        -Wextra 
        -Wpedantic
    )
endif()

# Set ProjectBackend as the startup project
set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ProjectBackend)

# Filters
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/src" PREFIX "Source Files" FILES ${ProjectBackend_SOURCES})

# Enable solution folders
set_property(GLOBAL PROPERTY USE_FOLDERS ON)