cmake_minimum_required (VERSION 3.0)

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RELEASE")
endif()

project (lor)

add_subdirectory(src)
add_subdirectory(programs)

install (DIRECTORY "${CMAKE_SOURCE_DIR}/include/lor"
         DESTINATION include)
