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

set(LIB_NAME "open1722" )

file(GLOB LIB_SOURCES *.c)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux" OR ${CMAKE_SYSTEM_NAME} STREQUAL "QNX")
    add_library(${LIB_NAME} SHARED ${LIB_SOURCES})
elseif(DEFINED ENV{ZEPHYR_BASE})
    add_library(${LIB_NAME} STATIC ${LIB_SOURCES})
    target_link_libraries(${LIB_NAME} PRIVATE zephyr_interface)
else()
    add_library(${LIB_NAME} STATIC ${LIB_SOURCES})
endif()
target_compile_options(${LIB_NAME} PRIVATE -Wall -Wextra)
target_include_directories(${LIB_NAME} PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
set_target_properties(${LIB_NAME} PROPERTIES VERSION ${PROJECT_VERSION})

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux" OR ${CMAKE_SYSTEM_NAME} STREQUAL "QNX")
    add_library(${LIB_NAME}custom SHARED ${LIB_SOURCES})
elseif(DEFINED ENV{ZEPHYR_BASE})
    add_library(${LIB_NAME}custom STATIC ${LIB_SOURCES})
    target_link_libraries(${LIB_NAME}custom PRIVATE zephyr_interface)
else()
    add_library(${LIB_NAME}custom STATIC ${LIB_SOURCES})
endif()
target_compile_options(${LIB_NAME}custom PRIVATE -Wall -Wextra)
target_include_directories(${LIB_NAME}custom PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
set_target_properties(${LIB_NAME}custom PROPERTIES VERSION ${PROJECT_VERSION})

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux" OR ${CMAKE_SYSTEM_NAME} STREQUAL "QNX")
    install(TARGETS ${LIB_NAME}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(TARGETS ${LIB_NAME}custom
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()

add_subdirectory(avtp)