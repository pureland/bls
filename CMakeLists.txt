cmake_minimum_required (VERSION 2.6)
project(bls CXX ASM)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if( APPLE )
    # Apple Specific Options Here
    message( STATUS "Configuring Catenas on OS X" )
    set( CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -stdlib=libc++ -Wall" )
endif( APPLE )

if(BLS_SWAP_G)
     set( CMAKE_CXX_FLAGS BLS_SWAP_G )
endif(BLS_SWAP_G)
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

add_library(bls_256_lib SHARED src/bls_256_lib.cpp)
target_include_directories(bls_256_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/mcl/include)

target_link_libraries(bls_256_lib ${LIBS})


file(GLOB BLS_HEADERS include/bls/bls_256_lib.hpp)

install(TARGETS bls_256_lib DESTINATION lib)
install(FILES ${BLS_HEADERS} DESTINATION include/bls)
