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
find_package(cmocka 1.1.0 REQUIRED)

add_executable(test-can test-can.c)
target_link_libraries(test-can open1722 cmocka m)
target_include_directories(test-can PUBLIC ../include)
add_test(NAME test-can COMMAND test-can)

add_executable(test-aaf test-aaf.c)
target_link_libraries(test-aaf open1722 cmocka)
target_include_directories(test-aaf PUBLIC ../include)
add_test(NAME test-aaf COMMAND test-aaf)

add_executable(test-avtp test-avtp.c)
target_link_libraries(test-avtp open1722 cmocka)
target_include_directories(test-avtp PUBLIC ../include)
add_test(NAME test-avtp COMMAND test-avtp)

add_executable(test-crf test-crf.c)
target_link_libraries(test-crf open1722 cmocka)
target_include_directories(test-crf PUBLIC ../include)
add_test(NAME test-crf COMMAND test-crf)

add_executable(test-cvf test-cvf.c)
target_link_libraries(test-cvf open1722 cmocka)
target_include_directories(test-cvf PUBLIC ../include)
add_test(NAME test-cvf COMMAND test-cvf)

add_executable(test-rvf test-rvf.c)
target_link_libraries(test-rvf open1722 cmocka)
target_include_directories(test-rvf PUBLIC ../include)
add_test(NAME test-rvf COMMAND test-rvf)

add_executable(test-vss test-vss.c)
target_link_libraries(test-vss open1722 open1722custom cmocka)
target_include_directories(test-vss PUBLIC ../include)
add_test(NAME test-vss COMMAND test-vss)

add_dependencies(unittests test-can test-aaf
                test-avtp test-crf test-cvf
                test-rvf test-vss)