cmake_minimum_required (VERSION 2.6)
project(bls CXX ASM)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# GMP
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARIES NAMES gmp libgmp)
find_library(GMPXX_LIBRARIES NAMES gmpxx libgmpxx)

message(" GMP_INCLUDE_DIR ${GMP_INCLUDE_DIR}")

include_directories(include/ mcl/include/ )
#include_directories(mcl/include/)
include_directories(/usr/local/include/)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
   message("OPEN SSL include directories:" ${OPENSSL_INCLUDE_DIR})
endif()

include_directories(${GMP_INCLUDE_DIRS})
include_directories( ${OPENSSL_INCLUDE_DIR})

add_subdirectory(mcl)

set(LIBS ${GMP_LIBRARIES} ${GMPXX_LIBRARIES} ${OPENSSL_CRYPTO_LIBRARY} mcl )
#message(${GMP_LIBRARIES} ${GMPXX_LIBRARIES})

add_library(bls_c256 SHARED src/bls_c256.cpp)
add_library(bls_c384 SHARED src/bls_c384.cpp)
add_library(bls_c384_256 SHARED src/bls_c384_256.cpp)
target_link_libraries(bls_c256 ${LIBS})
target_link_libraries(bls_c384 ${LIBS})
target_link_libraries(bls_c384_256 ${LIBS})

file(GLOB BLS_HEADERS include/bls/bls.h include/bls/bls.hpp)

install(TARGETS bls_c256 DESTINATION lib)
install(TARGETS bls_c384 DESTINATION lib)
install(TARGETS bls_c384_256 DESTINATION lib)
install(FILES ${BLS_HEADERS} DESTINATION include/bls)

add_executable(bls_c256_test test/bls_c256_test.cpp)
target_link_libraries(bls_c256_test bls_c256)
add_executable(bls_c384_test test/bls_c384_test.cpp)
target_link_libraries(bls_c384_test bls_c384)
add_executable(bls_c384_256_test test/bls_c384_256_test.cpp)
target_link_libraries(bls_c384_256_test bls_c384_256)
