set(RDMASERVER rdma_server)

include(CheckCCompilerFlag)
check_c_compiler_flag(--static-pie HAS_STATIC_PIE)
if(NOT HAS_STATIC_PIE)
    message(FATAL_ERROR "Compiler does NOT support --static-pie, try a new version greater than 8.0, current ${CMAKE_C_COMPILER_VERSION}")
endif()

set(ENV{PKG_CONFIG_PATH} "${CMAKE_SOURCE_DIR}/rdma-core/build-musl/lib/pkgconfig")
find_package(PkgConfig REQUIRED)
pkg_search_module(IBVERBS REQUIRED libibverbs)
pkg_search_module(MLX5 REQUIRED libmlx5)

if(NOT IBVERBS_FOUND)
    message(FATAL_ERROR "libibverbs not found, please install it via scripts/getibverbs or set PKG_CONFIG_PATH correctly")
endif()

if(NOT MLX5_FOUND)
    message(FATAL_ERROR "libmlx5 not found, please install it via scripts/getmlx5 or set PKG_CONFIG_PATH correctly")
endif()

MESSAGE(STATUS "LIBIBVERBS_VERSION: ${IBVERBS_VERSION}")
MESSAGE(STATUS "LIBMLX5_VERSION: ${MLX5_VERSION}")
MESSAGE(STATUS "IBVERBS_INCLUDE_DIRS: ${IBVERBS_INCLUDE_DIRS}")
MESSAGE(STATUS "IBVERBS_LIBRARY_DIRS: ${IBVERBS_LIBRARY_DIRS}")

set(CONSUMER_SOURCES
    src/main.c
    src/startup.c
    src/rdma.c
    src/dynlink.h
    src/pkeys.h
    src/rdma.h
    mmheap/mmheap.c
    mmheap/mmheap.h
    ../kmodule/tables/dynamic_params_table.c
    ../kmodule/tables/events_table.c
    ../kmodule/tables/flags_table.c
    ../include/tsc.h
    ../include/common.h
    ../include/events.h
    ../include/ioctl.h)

set(RDMASERVER_SOURCES
    src/server.c
    src/rdma.c
    src/rdma.h)

foreach(FILENAME ${CONSUMER_SOURCES})
  get_filename_component(TMP_NAME ${FILENAME} NAME)
  configure_file(${FILENAME} src/${TMP_NAME} COPYONLY)
endforeach()

if(PATH_FMT)
  add_definitions(-DPATH_FMT="${PATH_FMT}")
  message(STATUS "Custom path format ${PATH_FMT}")
endif()

configure_file(musl.specs musl.specs COPYONLY)
configure_file(script_x86-64.ld script_x86-64.ld COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../include/config.h.in 
               ${CMAKE_CURRENT_SOURCE_DIR}/src/config.h)

set(CMAKE_C_FLAGS_DEBUG "-ggdb -Og -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-Os -DNODEBUG -fno-strict-aliasing")

include_directories(
  src/
  mmheap/
  ../include
  ${IBVERBS_INCLUDE_DIRS}
)
link_directories(
  ${IBVERBS_LIBRARY_DIRS}
)

add_executable(${CONSUMER}    ${CONSUMER_SOURCES})
add_executable(${RDMASERVER}  ${RDMASERVER_SOURCES})
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_custom_command(TARGET ${CONSUMER} POST_BUILD
    COMMAND strip -R .symtab ${CONSUMER} -o ${CONSUMER}
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different consumer "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "strip consumer .symtab section"
    VERBATIM)
endif()

target_compile_options(${CONSUMER} PRIVATE -mno-sse -Wall -fno-stack-protector -fPIE -specs=musl.specs)
target_link_options(${CONSUMER} PRIVATE --static-pie -nostartfiles -specs=musl.specs)
# force linking with mlx5 to load the constructor
target_link_libraries(${CONSUMER} PRIVATE -Wl,--whole-archive;-lmlx5;-Wl,--no-whole-archive ibverbs)
set(CONSUMER_LINKER_SCRIPT "script_x86-64.ld")
set_target_properties(${CONSUMER} PROPERTIES LINK_FLAGS "-T${CONSUMER_LINKER_SCRIPT}")

target_link_options(${RDMASERVER} PRIVATE --static)
target_link_libraries(${RDMASERVER} PRIVATE -Wl,--whole-archive;-lmlx5;-Wl,--no-whole-archive ibverbs)
