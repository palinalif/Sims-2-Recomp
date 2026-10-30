cmake_minimum_required(VERSION 3.22)
project(ts2_android LANGUAGES CXX)
get_filename_component(TS2_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../.." ABSOLUTE)
add_subdirectory("${TS2_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/core")
add_library(ts2_android SHARED bridge.cpp leaf_probe.cpp)
# OFF by default. Generated private inputs must never enter a distributable APK.
if(TS2_PRIVATE_LEAF_DIR)
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(FATAL_ERROR "Private differential probe is debug-only")
  endif()
  get_filename_component(PROBE_DIR "${TS2_PRIVATE_LEAF_DIR}" REALPATH)
  string(FIND "${PROBE_DIR}/" "${TS2_ROOT}/work/" PRIVATE_PREFIX)
  if(NOT PRIVATE_PREFIX EQUAL 0 OR NOT EXISTS "${PROBE_DIR}/probe.cpp")
    message(FATAL_ERROR "Private probe must be generated beneath ignored work/")
  endif()
  # Pinned upstream output uses GNU expression macros and unused scaffolding.
  # Compile it with the same ordinary NDK flags as the verified CLI fixture,
  # separately from the strict authored JNI/runtime target. Never edit the body.
  add_library(ts2_private_leaf OBJECT "${PROBE_DIR}/probe.cpp")
  set_target_properties(ts2_private_leaf PROPERTIES POSITION_INDEPENDENT_CODE ON)
  target_include_directories(ts2_private_leaf PRIVATE "${PROBE_DIR}"
    "${TS2_ROOT}/scripts/recomp")
  target_sources(ts2_android PRIVATE $<TARGET_OBJECTS:ts2_private_leaf>
    "${TS2_ROOT}/scripts/recomp/cache_caller_memory.cpp")
  target_compile_definitions(ts2_android PRIVATE TS2_PRIVATE_LEAF_PROBE=1)
endif()
target_link_libraries(ts2_android PRIVATE ts2_core android log c++_shared)
target_compile_options(ts2_android PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_options(ts2_android PRIVATE "-Wl,-z,max-page-size=16384")
