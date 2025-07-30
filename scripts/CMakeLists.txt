add_subdirectory(ctrl)
add_subdirectory(StressTesting)
add_subdirectory(tests)
add_custom_target(scripts
        DEPENDS ctrl attack stress tests)
