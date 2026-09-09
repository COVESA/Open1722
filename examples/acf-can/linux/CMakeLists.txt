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
target_include_directories(acf-can-talker PUBLIC ${PROJECT_SOURCE_DIR}/include ../ ../../)

add_executable(acf-can-listener EXCLUDE_FROM_ALL acf-can-listener.c ../acf-can-common.c)
target_link_libraries(acf-can-listener open1722 open1722examples)
target_include_directories(acf-can-listener PUBLIC ${PROJECT_SOURCE_DIR}/include ../ ../../)

add_executable(acf-can-bridge EXCLUDE_FROM_ALL acf-can-bridge.c ../acf-can-common.c)
target_link_libraries(acf-can-bridge open1722 open1722examples)
target_include_directories(acf-can-bridge PUBLIC ${PROJECT_SOURCE_DIR}/include ../ ../../)

add_executable(acf-canv2-talker EXCLUDE_FROM_ALL acf-can-talker.c ../acf-can-common.c)
target_compile_definitions(acf-canv2-talker PRIVATE AVTP_CAN_API=AVTP_CAN_API_CANV2)
target_link_libraries(acf-canv2-talker open1722 open1722examples)
target_include_directories(acf-canv2-talker PUBLIC ${PROJECT_SOURCE_DIR}/include ../ ../../)

add_executable(acf-canv2-listener EXCLUDE_FROM_ALL acf-can-listener.c ../acf-can-common.c)
target_compile_definitions(acf-canv2-listener PRIVATE AVTP_CAN_API=AVTP_CAN_API_CANV2)
target_link_libraries(acf-canv2-listener open1722 open1722examples)
target_include_directories(acf-canv2-listener PUBLIC ${PROJECT_SOURCE_DIR}/include ../ ../../)

add_executable(acf-canv2-bridge EXCLUDE_FROM_ALL acf-can-bridge.c ../acf-can-common.c)
target_compile_definitions(acf-canv2-bridge PRIVATE AVTP_CAN_API=AVTP_CAN_API_CANV2)
target_link_libraries(acf-canv2-bridge open1722 open1722examples)
target_include_directories(acf-canv2-bridge PUBLIC ${PROJECT_SOURCE_DIR}/include ../ ../../)

add_executable(acf-can-brief-talker EXCLUDE_FROM_ALL acf-can-talker.c ../acf-can-common.c)
target_compile_definitions(acf-can-brief-talker PRIVATE AVTP_CAN_API=AVTP_CAN_API_CANBRIEF)
target_link_libraries(acf-can-brief-talker open1722 open1722examples)
target_include_directories(acf-can-brief-talker PUBLIC ${PROJECT_SOURCE_DIR}/include ../ ../../)

add_executable(acf-can-brief-listener EXCLUDE_FROM_ALL acf-can-listener.c ../acf-can-common.c)
target_compile_definitions(acf-can-brief-listener PRIVATE AVTP_CAN_API=AVTP_CAN_API_CANBRIEF)
target_link_libraries(acf-can-brief-listener open1722 open1722examples)
target_include_directories(acf-can-brief-listener PUBLIC ${PROJECT_SOURCE_DIR}/include ../ ../../)

add_executable(acf-can-brief-bridge EXCLUDE_FROM_ALL acf-can-bridge.c ../acf-can-common.c)
target_compile_definitions(acf-can-brief-bridge PRIVATE AVTP_CAN_API=AVTP_CAN_API_CANBRIEF)
target_link_libraries(acf-can-brief-bridge open1722 open1722examples)
target_include_directories(acf-can-brief-bridge PUBLIC ${PROJECT_SOURCE_DIR}/include ../ ../../)

add_executable(acf-can-brief-v2-talker EXCLUDE_FROM_ALL acf-can-talker.c ../acf-can-common.c)
target_compile_definitions(acf-can-brief-v2-talker PRIVATE AVTP_CAN_API=AVTP_CAN_API_CANBRIEFV2)
target_link_libraries(acf-can-brief-v2-talker open1722 open1722examples)
target_include_directories(acf-can-brief-v2-talker PUBLIC ${PROJECT_SOURCE_DIR}/include ../ ../../)

add_executable(acf-can-brief-v2-listener EXCLUDE_FROM_ALL acf-can-listener.c ../acf-can-common.c)
target_compile_definitions(acf-can-brief-v2-listener PRIVATE AVTP_CAN_API=AVTP_CAN_API_CANBRIEFV2)
target_link_libraries(acf-can-brief-v2-listener open1722 open1722examples)
target_include_directories(acf-can-brief-v2-listener PUBLIC ${PROJECT_SOURCE_DIR}/include ../ ../../)

add_executable(acf-can-brief-v2-bridge EXCLUDE_FROM_ALL acf-can-bridge.c ../acf-can-common.c)
target_compile_definitions(acf-can-brief-v2-bridge PRIVATE AVTP_CAN_API=AVTP_CAN_API_CANBRIEFV2)
target_link_libraries(acf-can-brief-v2-bridge open1722 open1722examples)
target_include_directories(acf-can-brief-v2-bridge PUBLIC ${PROJECT_SOURCE_DIR}/include ../ ../../)

add_dependencies(examples acf-can-talker acf-can-listener acf-can-bridge 
                acf-canv2-talker acf-canv2-listener acf-canv2-bridge
                acf-can-brief-talker acf-can-brief-listener acf-can-brief-bridge
                acf-can-brief-v2-talker acf-can-brief-v2-listener acf-can-brief-v2-bridge)

install(TARGETS
    acf-can-listener
    acf-can-talker
    acf-can-bridge
    acf-canv2-listener
    acf-canv2-talker
    acf-canv2-bridge
    acf-can-brief-listener
    acf-can-brief-talker
    acf-can-brief-bridge
    acf-can-brief-v2-listener
    acf-can-brief-v2-talker
    acf-can-brief-v2-bridge
    RUNTIME DESTINATION bin
    OPTIONAL)