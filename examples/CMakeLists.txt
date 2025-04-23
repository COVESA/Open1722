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


add_library(open1722examples STATIC "common/common.c")
target_include_directories(open1722examples PRIVATE
    $<INSTALL_INTERFACE:include>
    ${CMAKE_CURRENT_SOURCE_DIR})
if (DEFINED ENV{ZEPHYR_BASE})
    target_link_libraries(open1722examples PRIVATE zephyr_interface)
endif()
add_dependencies(examples open1722examples)

# These examples can be also built for Zephyr
add_subdirectory(acf-can)

# These examples are currently exclusively for Linux
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
execute_process(
  COMMAND ldd --version
  OUTPUT_VARIABLE LDD_OUT
  ERROR_VARIABLE LDD_ERROR
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

message(STATUS "LDD version err: ${LDD_ERROR}")
message(STATUS "LDD version out: ${LDD_OUT}")

## MUSL ldd will output to stderr, while glibc ldd will output to stdout
if ("${LDD_ERROR}" MATCHES "musl")
    message(STATUS "musl detected via ldd — linking argp")
    target_link_libraries(open1722examples /usr/lib/libargp.a)
else()
    message(STATUS "musl not detected via ldd — not linking argp")
endif()
    add_subdirectory(aaf)
    add_subdirectory(crf)
    add_subdirectory(cvf)
    add_subdirectory(hello-world)
    add_subdirectory(acf-vss)
endif()


