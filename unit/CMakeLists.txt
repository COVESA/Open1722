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

add_executable(test-can test-can.c)
target_link_libraries(test-can open1722 cmocka m)
target_include_directories(test-can PUBLIC ../include)
add_test(NAME test-can COMMAND test-can)

set_source_files_properties(test-can.c PROPERTIES LANGUAGE CXX)
add_executable(test-can-cpp test-can.c)
target_link_libraries(test-can-cpp open1722 cmocka m)
target_include_directories(test-can-cpp PUBLIC ../include)
add_test(NAME test-can-cpp COMMAND test-can-cpp)

add_executable(test-aaf test-aaf.c)
target_link_libraries(test-aaf open1722 cmocka)
target_include_directories(test-aaf PUBLIC ../include)
add_test(NAME test-aaf COMMAND test-aaf)

set_source_files_properties(test-aaf.c PROPERTIES LANGUAGE CXX)
add_executable(test-aaf-cpp test-aaf.c)
target_link_libraries(test-aaf-cpp open1722 cmocka)
target_include_directories(test-aaf-cpp PUBLIC ../include)
add_test(NAME test-aaf-cpp COMMAND test-aaf-cpp)

add_executable(test-avtp test-avtp.c)
target_link_libraries(test-avtp open1722 cmocka)
target_include_directories(test-avtp PUBLIC ../include)
add_test(NAME test-avtp COMMAND test-avtp)

set_source_files_properties(test-avtp.c PROPERTIES LANGUAGE CXX)
add_executable(test-avtp-cpp test-avtp.c)
target_link_libraries(test-avtp-cpp open1722 cmocka)
target_include_directories(test-avtp-cpp PUBLIC ../include)
add_test(NAME test-avtp-cpp COMMAND test-avtp-cpp)

add_executable(test-crf test-crf.c)
target_link_libraries(test-crf open1722 cmocka)
target_include_directories(test-crf PUBLIC ../include)
add_test(NAME test-crf COMMAND test-crf)

set_source_files_properties(test-crf.c PROPERTIES LANGUAGE CXX)
add_executable(test-crf-cpp test-crf.c)
target_link_libraries(test-crf-cpp open1722 cmocka)
target_include_directories(test-crf-cpp PUBLIC ../include)
add_test(NAME test-crf-cpp COMMAND test-crf-cpp)

add_executable(test-cvf test-cvf.c)
target_link_libraries(test-cvf open1722 cmocka)
target_include_directories(test-cvf PUBLIC ../include)
add_test(NAME test-cvf COMMAND test-cvf)

set_source_files_properties(test-cvf.c PROPERTIES LANGUAGE CXX)
add_executable(test-cvf-cpp test-cvf.c)
target_link_libraries(test-cvf-cpp open1722 cmocka)
target_include_directories(test-cvf-cpp PUBLIC ../include)
add_test(NAME test-cvf-cpp COMMAND test-cvf-cpp)

add_executable(test-rvf test-rvf.c)
target_link_libraries(test-rvf open1722 cmocka)
target_include_directories(test-rvf PUBLIC ../include)
add_test(NAME test-rvf COMMAND test-rvf)

set_source_files_properties(test-rvf.c PROPERTIES LANGUAGE CXX)
add_executable(test-rvf-cpp test-rvf.c)
target_link_libraries(test-rvf-cpp open1722 cmocka)
target_include_directories(test-rvf-cpp PUBLIC ../include)
add_test(NAME test-rvf-cpp COMMAND test-rvf-cpp)

add_executable(test-tscf test-tscf.c)
target_link_libraries(test-tscf open1722 cmocka)
target_include_directories(test-tscf PUBLIC ../include)
add_test(NAME test-tscf COMMAND test-tscf)

set_source_files_properties(test-tscf.c PROPERTIES LANGUAGE CXX)
add_executable(test-tscf-cpp test-tscf.c)
target_link_libraries(test-tscf-cpp open1722 cmocka)
target_include_directories(test-tscf-cpp PUBLIC ../include)
add_test(NAME test-tscf-cpp COMMAND test-tscf-cpp)

add_executable(test-ntscf test-ntscf.c)
target_link_libraries(test-ntscf open1722 cmocka)
target_include_directories(test-ntscf PUBLIC ../include)
add_test(NAME test-ntscf COMMAND test-ntscf)

set_source_files_properties(test-ntscf.c PROPERTIES LANGUAGE CXX)
add_executable(test-ntscf-cpp test-ntscf.c)
target_link_libraries(test-ntscf-cpp open1722 cmocka)
target_include_directories(test-ntscf-cpp PUBLIC ../include)
add_test(NAME test-ntscf-cpp COMMAND test-ntscf-cpp)

add_executable(test-vss test-vss.c)
target_link_libraries(test-vss open1722 open1722custom cmocka)
target_include_directories(test-vss PUBLIC ../include)
add_test(NAME test-vss COMMAND test-vss)

set_source_files_properties(test-vss.c PROPERTIES LANGUAGE CXX)
add_executable(test-vss-cpp test-vss.c)
target_link_libraries(test-vss-cpp open1722 open1722custom cmocka)
target_include_directories(test-vss-cpp PUBLIC ../include)
add_test(NAME test-vss-cpp COMMAND test-vss-cpp)

add_executable(test-flexray test-flexray.c)
target_link_libraries(test-flexray open1722 cmocka)
target_include_directories(test-flexray PUBLIC ../include)
add_test(NAME test-flexray COMMAND test-flexray)

set_source_files_properties(test-flexray.c PROPERTIES LANGUAGE CXX)
add_executable(test-flexray-cpp test-flexray.c)
target_link_libraries(test-flexray-cpp open1722 cmocka)
target_include_directories(test-flexray-cpp PUBLIC ../include)
add_test(NAME test-flexray-cpp COMMAND test-flexray-cpp)

add_executable(test-lin test-lin.c)
target_link_libraries(test-lin open1722 cmocka)
target_include_directories(test-lin PUBLIC ../include)
add_test(NAME test-lin COMMAND test-lin)

set_source_files_properties(test-lin.c PROPERTIES LANGUAGE CXX)
add_executable(test-lin-cpp test-lin.c)
target_link_libraries(test-lin-cpp open1722 cmocka)
target_include_directories(test-lin-cpp PUBLIC ../include)
add_test(NAME test-lin-cpp COMMAND test-lin-cpp)

add_executable(test-most test-most.c)
target_link_libraries(test-most open1722 cmocka)
target_include_directories(test-most PUBLIC ../include)
add_test(NAME test-most COMMAND test-most)

set_source_files_properties(test-most.c PROPERTIES LANGUAGE CXX)
add_executable(test-most-cpp test-most.c)
target_link_libraries(test-most-cpp open1722 cmocka)
target_include_directories(test-most-cpp PUBLIC ../include)
add_test(NAME test-most-cpp COMMAND test-most-cpp)

add_executable(test-gpc test-gpc.c)
target_link_libraries(test-gpc open1722 cmocka)
target_include_directories(test-gpc PUBLIC ../include)
add_test(NAME test-gpc COMMAND test-gpc)

set_source_files_properties(test-gpc.c PROPERTIES LANGUAGE CXX)
add_executable(test-gpc-cpp test-gpc.c)
target_link_libraries(test-gpc-cpp open1722 cmocka)
target_include_directories(test-gpc-cpp PUBLIC ../include)
add_test(NAME test-gpc-cpp COMMAND test-gpc-cpp)

add_executable(test-sensor test-sensor.c)
target_link_libraries(test-sensor open1722 cmocka)
target_include_directories(test-sensor PUBLIC ../include)
add_test(NAME test-sensor COMMAND test-sensor)

set_source_files_properties(test-sensor.c PROPERTIES LANGUAGE CXX)
add_executable(test-sensor-cpp test-sensor.c)
target_link_libraries(test-sensor-cpp open1722 cmocka)
target_include_directories(test-sensor-cpp PUBLIC ../include)
add_test(NAME test-sensor-cpp COMMAND test-sensor-cpp)

add_executable(test-udp test-udp.c)
target_link_libraries(test-udp open1722 cmocka)
target_include_directories(test-udp PUBLIC ../include)
add_test(NAME test-udp COMMAND test-udp)

set_source_files_properties(test-udp.c PROPERTIES LANGUAGE CXX)
add_executable(test-udp-cpp test-udp.c)
target_link_libraries(test-udp-cpp open1722 cmocka)
target_include_directories(test-udp-cpp PUBLIC ../include)
add_test(NAME test-udp-cpp COMMAND test-udp-cpp)

add_executable(test-commonheader test-commonheader.c)
target_link_libraries(test-commonheader open1722 cmocka)
target_include_directories(test-commonheader PUBLIC ../include)
add_test(NAME test-commonheader COMMAND test-commonheader)

set_source_files_properties(test-commonheader.c PROPERTIES LANGUAGE CXX)
add_executable(test-commonheader-cpp test-commonheader.c)
target_link_libraries(test-commonheader-cpp open1722 cmocka)
target_include_directories(test-commonheader-cpp PUBLIC ../include)
add_test(NAME test-commonheader-cpp COMMAND test-commonheader-cpp)

add_dependencies(unittests test-can test-aaf
                test-avtp test-crf test-cvf
                test-rvf test-vss test-tscf test-ntscf
                test-flexray test-lin test-most test-gpc test-sensor
                test-udp test-commonheader test-commonheader-cpp
                test-vss-cpp test-tscf-cpp test-ntscf-cpp test-flexray-cpp test-lin-cpp
                test-most-cpp test-gpc-cpp test-sensor-cpp test-udp-cpp 
                test-can-cpp test-aaf-cpp test-avtp-cpp test-crf-cpp test-cvf-cpp test-rvf-cpp)