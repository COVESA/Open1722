#
# Copyright (c) 2024, COVESA
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    # Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    # Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    # Neither the name of COVESA nor the names of its contributors may be
#      used to endorse or promote products derived from this software without
#      specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# SPDX-License-Identifier: BSD-3-Clause
#

include(CTest)
find_package(cmocka 1.1.0 QUIET)

if (NOT cmocka_FOUND)
  message(STATUS "cmocka not found, tests will not be built")
  return()
endif()

target_compile_options(open1722 PRIVATE -coverage)
target_link_options(open1722 PRIVATE -coverage)
target_compile_options(open1722custom PRIVATE -coverage)
target_link_options(open1722custom PRIVATE -coverage)

# Function to create dual tests (C and C++ compilation) for the same source file
function(add_dual_test TEST_NAME SOURCE_FILE)
    # Parse additional arguments for extra libraries
    set(EXTRA_LIBS ${ARGN})
    set(BASE_LIBS open1722 cmocka ${EXTRA_LIBS})
    
    # C version
    add_executable(${TEST_NAME} ${SOURCE_FILE})
    target_link_libraries(${TEST_NAME} ${BASE_LIBS})
    target_include_directories(${TEST_NAME} PUBLIC ../include)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    
    # C++ version (compile same source file as C++)
    set_source_files_properties(${SOURCE_FILE} PROPERTIES LANGUAGE CXX)
    add_executable(${TEST_NAME}-cpp ${SOURCE_FILE})
    target_link_libraries(${TEST_NAME}-cpp ${BASE_LIBS})
    target_include_directories(${TEST_NAME}-cpp PUBLIC ../include)
    add_test(NAME ${TEST_NAME}-cpp COMMAND ${TEST_NAME}-cpp)
    
    # Automatically add both targets to unittests dependencies
    add_dependencies(unittests ${TEST_NAME} ${TEST_NAME}-cpp)
endfunction()

# Create dual tests for all modules
add_dual_test(test-can test-can.c m)
add_dual_test(test-aaf test-aaf.c)
add_dual_test(test-avtp test-avtp.c)
add_dual_test(test-crf test-crf.c)
add_dual_test(test-cvf test-cvf.c)
add_dual_test(test-rvf test-rvf.c)
add_dual_test(test-tscf test-tscf.c)
add_dual_test(test-ntscf test-ntscf.c)
add_dual_test(test-vss test-vss.c open1722custom)
add_dual_test(test-flexray test-flexray.c)
add_dual_test(test-lin test-lin.c)
add_dual_test(test-most test-most.c)
add_dual_test(test-gpc test-gpc.c)
add_dual_test(test-sensor test-sensor.c)
add_dual_test(test-udp test-udp.c)
add_dual_test(test-commonheader test-commonheader.c)