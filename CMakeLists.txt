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

cmake_minimum_required(VERSION 3.20)
project(open1722 VERSION 0.1.0 LANGUAGES C DESCRIPTION "Library implementing IEEE 1722")
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

# Generate compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS "ON")

# Compiler setting
add_compile_options(-Wfatal-errors)
find_program(CCACHE_BIN ccache)
if(CCACHE_BIN)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ${CCACHE_BIN})
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ${CCACHE_BIN})
  message("Use ccache from ${CCACHE_BIN}")
endif()

add_subdirectory(src)
add_custom_target(examples)
add_subdirectory(examples EXCLUDE_FROM_ALL)

enable_testing()
add_custom_target(unittests)
add_subdirectory(unit EXCLUDE_FROM_ALL)

install(DIRECTORY include/ DESTINATION include)
install(TARGETS open1722 EXPORT Open1722Targets DESTINATION lib)

#### Export Configuration #####################################################

install(EXPORT Open1722Targets FILE Open1722Targets.cmake DESTINATION lib/cmake/Open1722)

include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/Open1722Config.cmake"
    INSTALL_DESTINATION "lib/cmake/Open1722"
    NO_SET_AND_CHECK_MACRO
    NO_CHECK_REQUIRED_COMPONENTS_MACRO)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/Open1722ConfigVersion.cmake
    VERSION "${Open1722_VERSION_MAJOR}.${Open1722_VERSION_MINOR}"
    COMPATIBILITY AnyNewerVersion)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/Open1722Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/Open1722ConfigVersion.cmake
    DESTINATION lib/cmake/Open1722)

export(EXPORT Open1722Targets FILE ${CMAKE_CURRENT_BINARY_DIR}/Open1722Targets.cmake)

#### Packaging ################################################################

include(InstallRequiredSystemLibraries)
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION_MAJOR "${Open1722_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${Open1722_VERSION_MINOR}")
# set(CPACK_PACKAGE_DIRECTORY "${PROJECT_BINARY_DIR}/release")
set(CPACK_GENERATOR "TGZ" "DEB")
set(CPACK_SOURCE_GENERATOR "TGZ" "DEB")

# Debian package
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Adriaan Niess [Robert Bosch GmbH]")

include(CPack)
