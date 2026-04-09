cmake_minimum_required(VERSION 3.20)
project(virtualization_project LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_program(CARGO_EXECUTABLE cargo REQUIRED)

set(RUST_CRATE_DIR "${CMAKE_SOURCE_DIR}/rust/vm_core")
set(RUST_TARGET_DIR "${RUST_CRATE_DIR}/target")
set(RUST_STATIC_LIB "${RUST_TARGET_DIR}/release/libvm_core.a")
file(GLOB_RECURSE RUST_VM_CORE_SOURCES CONFIGURE_DEPENDS "${RUST_CRATE_DIR}/src/*.rs")

add_custom_command(
    OUTPUT "${RUST_STATIC_LIB}"
    COMMAND "${CARGO_EXECUTABLE}" build --release --manifest-path "${RUST_CRATE_DIR}/Cargo.toml"
    WORKING_DIRECTORY "${RUST_CRATE_DIR}"
    DEPENDS "${RUST_CRATE_DIR}/Cargo.toml" ${RUST_VM_CORE_SOURCES}
    COMMENT "Building Rust vm_core static library"
    VERBATIM
)

add_custom_target(vm_core_build ALL DEPENDS "${RUST_STATIC_LIB}")

add_library(vm_core STATIC IMPORTED GLOBAL)
set_target_properties(vm_core PROPERTIES IMPORTED_LOCATION "${RUST_STATIC_LIB}")
add_dependencies(vm_core vm_core_build)

add_executable(vm_host
    cpp/src/main.cpp
)

target_include_directories(vm_host PRIVATE cpp/include)
target_link_libraries(vm_host PRIVATE vm_core dl pthread m)
