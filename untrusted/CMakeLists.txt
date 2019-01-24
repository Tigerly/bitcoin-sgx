set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wall -Wno-sign-compare -Wno-deprecated")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

set_directory_properties(PROPERTIES
        ADDITIONAL_MAKE_CLEAN_FILES Enclave_u.c
        ADDITIONAL_MAKE_CLEAN_FILES Enclave_u.h)

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.c ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.h
        COMMAND ${SGX_EDGER8R} --untrusted Enclave.edl
        --search-path ${CMAKE_SOURCE_DIR}/common/ # Enclave.edl
        --search-path ${SGX_SDK}/include
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(main main.cpp enclave_utils.cpp Enclave_u.c)

include_directories(
        ${SGXSDK_INCLUDE_DIRS}
)

target_link_libraries(main
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB} -lpthread)

add_dependencies(main enclave)