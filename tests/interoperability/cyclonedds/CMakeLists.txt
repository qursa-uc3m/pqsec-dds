cmake_minimum_required(VERSION 3.16)
project(pqsec_interop_cyclonedds C)

find_package(CycloneDDS REQUIRED)
idlc_generate(TARGET interop_type FILES ${CMAKE_CURRENT_SOURCE_DIR}/../Interop.idl)
add_executable(cyclonedds_app app.c)
target_link_libraries(cyclonedds_app interop_type CycloneDDS::ddsc)
