cmake_minimum_required(VERSION 3.10)

# set the project name
project(Dpf VERSION 0.1)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 17)

message(STATUS "Message: " ${CMAKE_CXX_FLAGS})
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_BUILD_TYPE Debug)


enable_testing()
find_package(OpenSSL REQUIRED)
set(OPENSSL_USE_STATIC_LIBS TRUE)

include_directories(${OPENSSL_INCLUDE_DIR})

add_library(Utils utils.cpp)
#target_link_libraries(Utils OpenSSL::SSL)
#target_link_libraries(Utils OpenSSL::Crypto)
add_library(Coding coding.cpp)
add_library(Params params.cpp)

add_library(DpfTree dpf_tree.cpp)
add_library(ShamirDPF shamir_dpf.cpp)
add_library(MultiPartyDPF multiparty_dpf.cpp)
add_library(Woodruff woodruff.cpp)

add_library(Server server.cpp)
add_library(Client client.cpp)

add_library(Interpolation interpolation.cpp)

# add executables 
add_executable(correctness_tests correctness_tests.cpp)
target_link_libraries(correctness_tests DpfTree)
target_link_libraries(correctness_tests ShamirDPF)
target_link_libraries(correctness_tests Utils)
target_link_libraries(correctness_tests OpenSSL::SSL)
target_link_libraries(correctness_tests OpenSSL::Crypto)
target_link_libraries(correctness_tests Coding)
target_link_libraries(correctness_tests Server)
target_link_libraries(correctness_tests Client)
target_link_libraries(correctness_tests MultiPartyDPF)
target_link_libraries(correctness_tests Params)
target_link_libraries(correctness_tests Woodruff)
target_link_libraries(correctness_tests Interpolation)

# target_compile_options(correctness_tests PRIVATE -Wall -Wextra -Wpedantic -O3 -Ofast)
