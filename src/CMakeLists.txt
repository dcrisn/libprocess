set(LIBRARY_MAJOR_VERSION 0)
set(LIBRARY_MINOR_VERSION 0)
set(LIBRARY_PATCH_NUMBER 1)
set(LIBRARY_VERSION_STRING
    "${LIBRARY_MAJOR_VERSION}.${LIBRARY_MINOR_VERSION}.${LIBRARY_PATCH_NUMBER}")

SET(TARP_PACKAGE_FILES "${CMAKE_SOURCE_DIR}/cmake")

SET(public_headers
    ${CMAKE_SOURCE_DIR}/src/include/
)

add_library(libprocess SHARED
    subprocess.cpp
    demonic.cpp

    # copied from libtarp to avoid depending on it.
    ioutils.cxx
    string_utils.cxx
)

add_library(tarp::process ALIAS libprocess)

set_target_properties(libprocess PROPERTIES
    VERSION ${LIBRARY_VERSION_STRING}
    SOVERSION ${LIBRARY_MAJOR_VERSION}
    LIBRARY_OUTPUT_NAME process
    EXPORT_NAME process
)

target_include_directories(libprocess PUBLIC
    $<INSTALL_INTERFACE:include/>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/include/>
)

target_include_directories(libprocess PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/>
)

target_link_libraries(libprocess PUBLIC
    asio
)

########################################
## Build artifact installation rules  #
#######################################
#
INSTALL(DIRECTORY ${public_headers}/ DESTINATION include/)

set_target_properties(libprocess
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

#################################################
# Artifact installation and target export
#################################################
SET(CMAKE_EXPORT_FILE "tarp_process-targets")

INSTALL(TARGETS libprocess asio
    EXPORT ${CMAKE_EXPORT_FILE}
    LIBRARY DESTINATION lib/
    ARCHIVE DESTINATION lib/
    RUNTIME DESTINATION bin/
)

# Create the exports file; other projects, when package_find-ing
# this project, can then import this exports file and get all the
# exported targets.
export(TARGETS asio
    FILE ${PROJECT_BINARY_DIR}/${CMAKE_EXPORT_FILE}.cmake
)
export(TARGETS libprocess NAMESPACE tarp::
    APPEND FILE ${PROJECT_BINARY_DIR}/${CMAKE_EXPORT_FILE}.cmake
)

# Some standard paths according to gnu guidelines
include(GNUInstallDirs)

# Where to put the cmake files that can be used by other cmake projects;
# NOTE: CMAKE_INSTALL_LIBDIR is from the GNUInstallDirs import.
SET(CMAKE_INSTALLATION_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/tarp/)
SET(PKGCONFIG_INSTALLATION_DIR ${CMAKE_INSTALL_LIBDIR}/pkgconfig/)

SET(version_config_file ${PROJECT_BINARY_DIR}/tarp_process-config-version.cmake)
SET(project_config_file ${PROJECT_BINARY_DIR}/tarp_process-config.cmake)
SET(pkgconfig_pc_file ${PROJECT_BINARY_DIR}/tarp_process.pc)

# CMake helpers for generating a package config file (used below).
include(CMakePackageConfigHelpers)

# Generate the package-version cmake config file into the build directory
write_basic_package_version_file(
    ${version_config_file}
    VERSION ${LIBRARY_VERSION_STRING}
    COMPATIBILITY SameMajorVersion)

# generate the config.cmake file into the build directory.
# this file is used by cmake's find_package.
# Allow other projects to do: find_package(tarp_package).
configure_package_config_file(
    ${TARP_PACKAGE_FILES}/libprocess-config.cmake.in
    ${project_config_file}
    INSTALL_DESTINATION ${CMAKE_INSTALLATION_DIR})

# generate the .pc file used by the standard Linux pkg-config utility,
# and by the cmake check_modules wrapper/interface to it.
# Allow other projects to do: pkg_check_modules(tarp::process REQUIRED tarp_process)
configure_file(
    "${TARP_PACKAGE_FILES}/libprocess.pc.in"
    "${pkgconfig_pc_file}"
    @ONLY
    )

# Install the actual cmake exports file that previous commands
# have gradually populated.
INSTALL(
    EXPORT ${CMAKE_EXPORT_FILE}
    DESTINATION ${CMAKE_INSTALLATION_DIR}
    NAMESPACE tarp::
)

# Install config.cmake and config-version.cmake files.
install(
    FILES
       ${project_config_file}
       ${version_config_file}
    DESTINATION
       ${CMAKE_INSTALLATION_DIR}
)

# install .pc pkg-config file.
install(
    FILES
        "${pkgconfig_pc_file}"
    DESTINATION
        "${PKGCONFIG_INSTALLATION_DIR}"
)
