# Static Linux/AArch64 validation, separate from host and Android builds.
# Requires Zig 0.14.0 wrappers from the documented no-root host toolchain.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
if(DEFINED ENV{TS2_HOST_TOOLCHAIN})
  set(_ts2_tc "$ENV{TS2_HOST_TOOLCHAIN}")
else()
  get_filename_component(_ts2_tc "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
  string(APPEND _ts2_tc "/.local-tools/toolchain/bin")
endif()
set(CMAKE_CXX_COMPILER "${_ts2_tc}/zig-cxx" "-target" "aarch64-linux-musl")
set(CMAKE_AR "${_ts2_tc}/zig-ar")
set(CMAKE_RANLIB "${_ts2_tc}/zig-ranlib")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static")
# CMake prepends this command to add_test(COMMAND <executable-target> ...).
# Missing QEMU is a visible failure, never an implicit host execution/pass.
get_filename_component(_ts2_repo "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set(CMAKE_CROSSCOMPILING_EMULATOR "${_ts2_repo}/scripts/campaign/arm64-run.sh")
