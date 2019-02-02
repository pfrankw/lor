cmake_minimum_required (VERSION 3.0)

SET(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/lib)

include_directories(../include /usr/local/include)
link_directories(${LIBRARY_OUTPUT_PATH} /usr/local/lib)

add_executable(test_hs test_hs.c)

target_link_libraries(test_hs lor mbedtls mbedx509 mbedcrypto)

if (MINGW)
  target_link_libraries(test_hs ws2_32)
endif(MINGW)

SET(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wall")

if (NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "AppleClang")
  SET(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -mno-ms-bitfields" )
endif()

SET(CMAKE_C_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG} -g")
SET(CMAKE_C_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE} -s")
