add_executable(helloworld EXCLUDE_FROM_ALL helloworld.c)
add_executable(multithread EXCLUDE_FROM_ALL multithread.c)
add_executable(flood flood.c)
target_link_libraries(multithread PRIVATE pthread)
target_link_libraries(flood PRIVATE pthread)

add_custom_target(tests
        DEPENDS multithread helloworld flood)

include_directories(../../include)
