include_directories(${HyperCryptLib_SOURCE_DIR}/include)

add_library(libhypercrypt SHARED hypercrypt.c)
set_target_properties(libhypercrypt PROPERTIES
                                    PUBLIC_HEADER {HyperCryptLib_SOURCE_DIR}/include/hypercrypt.h)

add_executable(hypercrypt_test hypercrypt.c ../test/test.c)
add_custom_command(TARGET hypercrypt_test POST_BUILD COMMAND ${HyperCryptLib_SOURCE_DIR}/build/hypercrypt_test && rm ${HyperCryptLib_SOURCE_DIR}/build/hypercrypt_test)