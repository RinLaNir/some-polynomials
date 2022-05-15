### simplified copy of the CMakeLists.txt file of the HElib examples
cmake_minimum_required(VERSION 3.10.2 FATAL_ERROR)
## Use -std=c++17 as default.
set(CMAKE_CXX_STANDARD 17)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)
project(some-polynomials VERSION 1.0)

add_executable(helibdemo helibdemo.cpp)
add_executable(PowSums PowSums.cpp)
add_executable(E_2 E_2.cpp)
add_executable(E_3 E_3.cpp)

find_package(helib ${HELIB_VERSION} REQUIRED)
target_link_libraries(helibdemo helib)
target_link_libraries(PowSums helib)
target_link_libraries(E_2 helib)
target_link_libraries(E_3 helib)