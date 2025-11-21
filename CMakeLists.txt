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
# find_package(websocketpp CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# === websocket++ ===
FetchContent_Declare(websocketpp
GIT_REPOSITORY https://github.com/zaphoyd/websocketpp.git
  GIT_TAG 0.8.2)
FetchContent_GetProperties(websocketpp)
if(NOT websocketpp_POPULATED)
  FetchContent_Populate(websocketpp)
  add_subdirectory(${websocketpp_SOURCE_DIR} ${websocketpp_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()
# add interface library with all websocketpp dependencies
add_library(Websockets INTERFACE)
target_include_directories(Websockets INTERFACE ${websocketpp_SOURCE_DIR})
target_link_libraries(Websockets INTERFACE Boost::system Boost::thread Boost::regex)

# No C++20 modules
set(CMAKE_CXX_SCAN_FOR_MODULES OFF) 

# ProjectBackend executable
add_executable(ProjectBackend)

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
    Websockets INTERFACE ${CMAKE_SOURCE_DIR}/websocketpp/websocketpp
)

# Automatically links to these libs
target_link_libraries(ProjectBackend PRIVATE
    Websockets INTERFACE Boost::system Boost::thread Boost::regex
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