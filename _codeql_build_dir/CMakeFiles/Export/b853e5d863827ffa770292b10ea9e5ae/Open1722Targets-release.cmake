#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "open1722" for configuration "Release"
set_property(TARGET open1722 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(open1722 PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libopen1722.so.0.1.0"
  IMPORTED_SONAME_RELEASE "libopen1722.so.0.1.0"
  )

list(APPEND _cmake_import_check_targets open1722 )
list(APPEND _cmake_import_check_files_for_open1722 "${_IMPORT_PREFIX}/lib/libopen1722.so.0.1.0" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
