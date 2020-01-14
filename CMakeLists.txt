cmake_minimum_required(VERSION 3.15)
project(sandbox)

set(CMAKE_CXX_STANDARD 17)

add_executable(sandbox main.cpp)

find_package(Boost 1.65.1 REQUIRED COMPONENTS filesystem)
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(sandbox ${Boost_LIBRARIES})
endif()

target_link_libraries(sandbox cgroup)