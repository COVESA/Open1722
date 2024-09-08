cmake_minimum_required(VERSION 3.20)

project(Open1722 VERSION 0.1)

option(OPEN1722_BUILD_TESTS "Build tests" OFF)
option(OPEN1722_BUILD_EXAMPLES "Build tests" OFF)
option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

#### Libraries ################################################################

set(SOURCES
    "src/avtp/CommonHeader.c"
    "src/avtp/Crf.c"
    "src/avtp/Rvf.c"
    "src/avtp/Udp.c"
    "src/avtp/Utils.c"
    "src/avtp/aaf/Aaf.c"
    "src/avtp/aaf/Pcm.c"
    "src/avtp/acf/FlexRay.c"
    "src/avtp/acf/Gpc.c"
    "src/avtp/acf/Can.c"
    "src/avtp/acf/CanBrief.c"
    "src/avtp/acf/Lin.c"
    "src/avtp/acf/Most.c"
    "src/avtp/acf/AcfCommon.c"
    "src/avtp/acf/Ntscf.c"
    "src/avtp/acf/Sensor.c"
    "src/avtp/acf/SensorBrief.c"
    "src/avtp/acf/Tscf.c"
    "src/avtp/cvf/Cvf.c"
    "src/avtp/cvf/H264.c"
    "src/avtp/cvf/Jpeg2000.c"
    "src/avtp/cvf/Mjpeg.c"
)

if(BUILD_SHARED_LIBS)
    add_library(open1722 SHARED ${SOURCES})
else()
    add_library(open1722 STATIC ${SOURCES})
endif()

set_target_properties(open1722 PROPERTIES VERSION ${PROJECT_VERSION})

target_include_directories(open1722 PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)

#### Examples #################################################################

if (OPEN1722_BUILD_EXAMPLES)
    # Common library accross all examples
    add_library(open1722examples STATIC "examples/common/common.c")
    target_include_directories(open1722examples PRIVATE "examples" "include")

    # AAF listener app
    add_executable(aaf-listener "examples/aaf/aaf-listener.c")
    target_include_directories(aaf-listener PRIVATE "examples" "include")
    target_link_libraries(aaf-listener open1722 open1722examples)

    # AAF talker app
    add_executable(aaf-talker "examples/aaf/aaf-talker.c")
    target_include_directories(aaf-talker PRIVATE "examples" "include")
    target_link_libraries(aaf-talker open1722 open1722examples)

    # CAN talker app
    add_executable(acf-can-talker "examples/acf-can/acf-can-talker.c" "examples/acf-can/acf-can-common.c")
    target_include_directories(acf-can-talker PRIVATE "examples" "include")
    target_link_libraries(acf-can-talker open1722 open1722examples)

    # CAN listener app
    add_executable(acf-can-listener "examples/acf-can/acf-can-listener.c" "examples/acf-can/acf-can-common.c")
    target_include_directories(acf-can-listener PRIVATE "examples" "include")
    target_link_libraries(acf-can-listener open1722 open1722examples)

    # CRF talker app
    add_executable(crf-talker "examples/crf/crf-talker.c")
    target_include_directories(crf-talker PRIVATE "examples" "include")
    target_link_libraries(crf-talker open1722 open1722examples m)

    # CRF listener app
    add_executable(crf-listener "examples/crf/crf-listener.c")
    target_include_directories(crf-listener PRIVATE "examples" "include")
    target_link_libraries(crf-listener open1722 open1722examples m)

    # CVF talker app
    add_executable(cvf-talker "examples/cvf/cvf-talker.c")
    target_include_directories(cvf-talker PRIVATE "examples" "include")
    target_link_libraries(cvf-talker open1722 open1722examples)

    # CVF listener app
    add_executable(cvf-listener "examples/cvf/cvf-listener.c")
    target_include_directories(cvf-listener PRIVATE "examples" "include")
    target_link_libraries(cvf-listener open1722 open1722examples)

    # Hello-world talker app
    add_executable(hello-world-talker "examples/hello-world/hello-world-talker.c")
    target_include_directories(hello-world-talker PRIVATE "examples" "include")
    target_link_libraries(hello-world-talker open1722 open1722examples)

    # Hello-world listener app
    add_executable(hello-world-listener "examples/hello-world/hello-world-listener.c")
    target_include_directories(hello-world-listener PRIVATE "examples" "include")
    target_link_libraries(hello-world-listener open1722 open1722examples)
endif()

#### Tests ####################################################################

if (OPEN1722_BUILD_TESTS)
    enable_testing()

    # find_package(cmocka 1.1.0 REQUIRED)

    list(APPEND TEST_TARGETS test-aaf)
    list(APPEND TEST_TARGETS test-avtp)
    list(APPEND TEST_TARGETS test-can)
    list(APPEND TEST_TARGETS test-crf)
    list(APPEND TEST_TARGETS test-cvf)
    list(APPEND TEST_TARGETS test-rvf)
    # list(APPEND TEST_TARGETS test-stream)

    foreach(TEST_TARGET IN LISTS TEST_TARGETS)
        add_executable(${TEST_TARGET} "unit/${TEST_TARGET}.c")
        target_include_directories(${TEST_TARGET} PRIVATE "include")
        target_link_libraries(${TEST_TARGET} open1722 cmocka m)
        add_test(NAME ${TEST_TARGET} COMMAND "${PROJECT_BINARY_DIR}/${TEST_TARGET}")
    endforeach()
endif()

#### Install ##################################################################

install(TARGETS open1722 EXPORT Open1722Targets DESTINATION lib)
install(DIRECTORY "include/" DESTINATION include)

if (OPEN1722_BUILD_EXAMPLES)
    install(TARGETS
        aaf-listener
        aaf-talker
        acf-can-listener
        acf-can-talker
        crf-listener
        crf-talker
        cvf-listener
        cvf-talker
        DESTINATION bin)
endif()

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
