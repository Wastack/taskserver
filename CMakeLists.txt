cmake_minimum_required (VERSION 2.8)
set(CMAKE_LEGACY_CYGWIN_WIN32 0) # Remove when CMake >= 2.8.4 is required
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

include (CheckFunctionExists)
include (CheckStructHasMember)

set (HAVE_CMAKE true)
set (CMAKE_CXX_STANDARD 17)

project (taskd)
include (CXXSniffer)

set (PROJECT_VERSION "1.2.0")

OPTION(USE_GNUTLS "Build gnutls support." ON)

message ("-- Looking for SHA1 references")
if (EXISTS ${CMAKE_SOURCE_DIR}/.git/index)
  set (HAVE_COMMIT true)
  execute_process (COMMAND git log -1 --pretty=format:%h
                   WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                   OUTPUT_VARIABLE COMMIT)
  configure_file ( ${CMAKE_SOURCE_DIR}/commit.h.in
                   ${CMAKE_SOURCE_DIR}/commit.h)
  message ("-- Found SHA1 reference: ${COMMIT}")
endif (EXISTS ${CMAKE_SOURCE_DIR}/.git/index)

set (PACKAGE "${PROJECT_NAME}")
set (VERSION "${PROJECT_VERSION}")
set (PACKAGE_BUGREPORT "support@gothenburgbitfactory.org")
set (PACKAGE_NAME "${PACKAGE}")
set (PACKAGE_TARNAME "${PACKAGE}")
set (PACKAGE_VERSION "${VERSION}")
set (PACKAGE_STRING "${PACKAGE} ${VERSION}")

if (FREEBSD OR DRAGONFLY)
SET (TASKD_MAN1DIR man/man1  CACHE STRING "Installation directory for man pages, section 1")
SET (TASKD_MAN5DIR man/man5  CACHE STRING "Installation directory for man pages, section 5")
else (FREEBSD OR DRAGONFLY)
SET (TASKD_MAN1DIR share/man/man1  CACHE STRING "Installation directory for man pages, section 1")
SET (TASKD_MAN5DIR share/man/man5  CACHE STRING "Installation directory for man pages, section 5")
endif (FREEBSD OR DRAGONFLY)
SET (TASKD_DOCDIR  share/doc/taskd CACHE STRING "Installation directory for doc files")
SET (TASKD_EXTDIR  libexec/taskd   CACHE STRING "Installation directory for the extensions")
SET (TASKD_BINDIR  bin             CACHE STRING "Installation directory for the program")

message ("-- Looking for GnuTLS")
find_package (GnuTLS REQUIRED)
if (GNUTLS_FOUND)
  set (HAVE_LIBGNUTLS true)
  set (TASKD_INCLUDE_DIRS ${TASKD_INCLUDE_DIRS} ${GNUTLS_INCLUDE_DIR})
  set (TASKD_LIBRARIES    ${TASKD_LIBRARIES}    ${GNUTLS_LIBRARIES})
endif (GNUTLS_FOUND)

check_function_exists (timegm          HAVE_TIMEGM)
check_function_exists (get_current_dir_name HAVE_GET_CURRENT_DIR_NAME)

check_struct_has_member ("struct tm"   tm_gmtoff    time.h                   HAVE_TM_GMTOFF)
check_struct_has_member ("struct stat" st_birthtime "sys/types.h;sys/stat.h" HAVE_ST_BIRTHTIME)


message ("-- Looking for libuuid")
if (DARWIN OR FREEBSD OR OPENBSD)
  # Apple and FreeBSD include the uuid functions in their libc, rather than libuuid
  check_function_exists (uuid_unparse_lower HAVE_UUID_UNPARSE_LOWER)
else (DARWIN OR FREEBSD OR OPENBSD)
  find_path    (UUID_INCLUDE_DIR   uuid/uuid.h)
  find_library (UUID_LIBRARY NAMES uuid)
  if (UUID_INCLUDE_DIR AND UUID_LIBRARY)
    set (TASKD_INCLUDE_DIRS ${TASKD_INCLUDE_DIRS} ${UUID_INCLUDE_DIR})
    set (TASKD_LIBRARIES    ${TASKD_LIBRARIES}    ${UUID_LIBRARY})
    # Look for uuid_unparse_lower
    set (CMAKE_REQUIRED_INCLUDES  ${CMAKE_REQUIRED_INCLUDES}  ${UUID_INCLUDE_DIR})
    set (CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} ${UUID_LIBRARY})
    check_function_exists (uuid_unparse_lower HAVE_UUID_UNPARSE_LOWER)
  else (UUID_INCLUDE_DIR AND UUID_LIBRARY)
    message (FATAL_ERROR "-- libuuid not found.")
  endif (UUID_INCLUDE_DIR AND UUID_LIBRARY)
endif (DARWIN OR FREEBSD OR OPENBSD)

if (HAVE_UUID_UNPARSE_LOWER)
  message ("-- Found libuuid")
else (HAVE_UUID_UNPARSE_LOWER)
  message ("-- Found libuuid, using internal uuid_unparse_lower")
endif (HAVE_UUID_UNPARSE_LOWER)

if (SOLARIS)
  # accept() is in libsocket according to its manpage
  message("-- Looking for libsocket")
  find_library (SOCKET_LIBRARY NAMES socket)
  if (SOCKET_LIBRARY)
    set (TASKD_LIBRARIES    ${TASKD_LIBRARIES} ${SOCKET_LIBRARY})
  else (SOCKET_LIBRARY)
    message(FATAL_ERROR "-- libsocket not found.")
  endif (SOCKET_LIBRARY)

  # inet_ntop() is in libnsl according to its manpage
  message("-- Looking for libnsl")
  find_library (NSL_LIBRARY NAMES nsl)
  if (NSL_LIBRARY)
    set (TASKD_LIBRARIES    ${TASKD_LIBRARIES} ${NSL_LIBRARY})
  else (NSL_LIBRARY)
    message(FATAL_ERROR "-- libnsl not found.")
  endif (NSL_LIBRARY)
endif (SOLARIS)

message ("-- Configuring cmake.h")
configure_file (
  ${CMAKE_SOURCE_DIR}/cmake.h.in
  ${CMAKE_SOURCE_DIR}/cmake.h)

add_subdirectory (src)
add_subdirectory (doc)
if (EXISTS ${CMAKE_SOURCE_DIR}/test)
  add_subdirectory (test EXCLUDE_FROM_ALL)
endif (EXISTS ${CMAKE_SOURCE_DIR}/test)

set (doc_FILES NEWS ChangeLog INSTALL AUTHORS COPYING)
foreach (doc_FILE ${doc_FILES})
  install (FILES ${doc_FILE}  DESTINATION ${TASKD_DOCDIR})
endforeach (doc_FILE)

install (PROGRAMS src/taskdctl DESTINATION ${TASKD_BINDIR})

# ---

set (CPACK_SOURCE_GENERATOR "TGZ")
set (CPACK_SOURCE_PACKAGE_FILE_NAME ${PACKAGE_NAME}-${PACKAGE_VERSION})
set (CPACK_SOURCE_IGNORE_FILES  "CMakeCache" "CMakeFiles" "CPackConfig" "CPackSourceConfig"
                                "_CPack_Packages" "cmake_install" "install_manifest"
                                "Makefile$" "test" "package-config"
                                "src/taskd$" "src/tls" "/\\\\.gitignore" "/\\\\.git/" "swp$")
include (CPack)
