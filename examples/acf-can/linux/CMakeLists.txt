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

add_executable(acf-can-talker EXCLUDE_FROM_ALL acf-can-talker.c ../acf-can-common.c)
target_link_libraries(acf-can-talker open1722 open1722examples)
target_include_directories(acf-can-talker PUBLIC ${CMAKE_SOURCE_DIR}/include ../ ../../)

add_executable(acf-can-listener EXCLUDE_FROM_ALL acf-can-listener.c ../acf-can-common.c)
target_link_libraries(acf-can-listener open1722 open1722examples)
target_include_directories(acf-can-listener PUBLIC ${CMAKE_SOURCE_DIR}/include ../ ../../)

add_executable(acf-can-bridge EXCLUDE_FROM_ALL acf-can-bridge.c ../acf-can-common.c)
target_link_libraries(acf-can-bridge open1722 open1722examples)
target_include_directories(acf-can-bridge PUBLIC ${CMAKE_SOURCE_DIR}/include ../ ../../)

add_dependencies(examples acf-can-talker acf-can-listener acf-can-bridge)

install(TARGETS
    acf-can-listener
    acf-can-talker
    acf-can-bridge
    RUNTIME DESTINATION bin
    OPTIONAL)