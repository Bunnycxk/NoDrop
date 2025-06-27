add_executable(helloworld EXCLUDE_FROM_ALL helloworld.c)
add_executable(multithread EXCLUDE_FROM_ALL multithread.c)
add_executable(getpid EXCLUDE_FROM_ALL getpid.c)
target_link_libraries(multithread PRIVATE pthread)
target_link_libraries(getpid PRIVATE pthread)

add_custom_target(tests
        DEPENDS multithread helloworld getpid)

include_directories(../../include)
