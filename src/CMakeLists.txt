cmake_minimum_required (VERSION 3.0)

SET(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/lib)

include_directories(../include /usr/local/include)

add_library (lor autocircuit.c base32.c circuit.c crypto.c dir.c hs.c lor.c net.c relay.c utils.c)

SET(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -s -Wall")

if (NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
  SET(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -mno-ms-bitfields")
endif()

SET(CMAKE_C_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG}")
SET(CMAKE_C_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE}")

install (TARGETS lor DESTINATION lib)
