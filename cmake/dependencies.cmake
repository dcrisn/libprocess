include(FetchContent)

find_package( PkgConfig REQUIRED )

set(FETCHCONTENT_QUIET OFF CACHE BOOL "" FORCE)

SET(EXTERNAL_SOURCES_DIR "${CMAKE_SOURCE_DIR}/external")

#
###########
#  asio   #
###########
# use asio without boost
SET(ASIO_SRC_ROOT_DIR   "${EXTERNAL_SOURCES_DIR}/asio/")
SET(ASIO_INCLUDE_DIR ${ASIO_SRC_ROOT_DIR}/asio/include)
#SET(ASIO_LIB_REPOS_DIR   "${ASIO_SRC_ROOT_DIR}/repos")
#SET(ASIO_LIB_INSTALL_DIR "${ASIO_SRC_ROOT_DIR}-install")
SET(ASIO_GIT_TAG "asio-1-32-0")

FetchContent_Declare(
   asio
   GIT_REPOSITORY  https://github.com/chriskohlhoff/asio/
   GIT_TAG         ${ASIO_GIT_TAG}
   SOURCE_DIR      ${ASIO_SRC_ROOT_DIR}
 )
FetchContent_MakeAvailable(asio)

# add 'virtual' library for asio that we can 'link' against here.
# 'link' is in quotation mark above because we are not actually linking
# anything. The target is virtual in the sense that we merely set some
# key-value properties so that other targets can use the usual cmake calls
# against this library.
add_library(asio INTERFACE)
target_include_directories(asio INTERFACE 
    $<INSTALL_INTERFACE:include/>
    $<BUILD_INTERFACE:${ASIO_INCLUDE_DIR}>
)

#
############
# doctest  #
############
# c++-friendly testing framework
SET(DOCTEST_SRC_ROOT_DIR "${CMAKE_SOURCE_DIR}/external/doctest/")
#SET(ASIO_INCLUDE_DIR ${ASIO_SRC_ROOT_DIR}/asio/include)
SET(DOCTEST_GIT_TAG "v2.4.11")

if (BUILD_TESTS)
    FetchContent_Declare(
       doctest
       GIT_REPOSITORY  https://github.com/doctest/doctest/
       GIT_TAG         ${DOCTEST_GIT_TAG}
       SOURCE_DIR      ${DOCTEST_SRC_ROOT_DIR}
     )
    FetchContent_MakeAvailable(doctest)
endif()

