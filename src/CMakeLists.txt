cmake_minimum_required (VERSION 2.8)
include_directories (${CMAKE_SOURCE_DIR}
                     ${CMAKE_SOURCE_DIR}/src
                     ${CMAKE_SOURCE_DIR}/src/libshared/src
                     ${TASKD_INCLUDE_DIRS})

add_library (taskd admin.cpp
                   api.cpp
                   client.cpp
                   ConfigFile.cpp ConfigFile.h
                   config.cpp
                   daemon.cpp
                   diag.cpp
                   Database.cpp   Database.h
                   help.cpp
                   init.cpp
                   Server.cpp     Server.h
                   SimpleClient.cpp  SimpleClient.h
                   SimpleServer.cpp  SimpleServer.h
                   Task.cpp       Task.h
                   TCPClient.cpp  TCPClient.h
                   TLSClient.cpp  TLSClient.h
                   TCPServer.cpp  TCPServer.h
                   TLSServer.cpp  TLSServer.h
                   util.cpp       util.h)

add_library (libshared libshared/src/Color.cpp         libshared/src/Color.h
                       libshared/src/Datetime.cpp      libshared/src/Datetime.h
                       libshared/src/Duration.cpp      libshared/src/Duration.h
                       libshared/src/FS.cpp            libshared/src/FS.h
                       libshared/src/JSON.cpp          libshared/src/JSON.h
                       libshared/src/Lexer.cpp         libshared/src/Lexer.h
                       libshared/src/Log.cpp           libshared/src/Log.h
                       libshared/src/Msg.cpp           libshared/src/Msg.h
                       libshared/src/Pig.cpp           libshared/src/Pig.h
                       libshared/src/RX.cpp            libshared/src/RX.h
                       libshared/src/Timer.cpp         libshared/src/Timer.h
                       libshared/src/format.cpp        libshared/src/format.h
                       libshared/src/ip.cpp
                       libshared/src/shared.cpp        libshared/src/shared.h
                       libshared/src/unicode.cpp       libshared/src/unicode.h
                       libshared/src/utf8.cpp          libshared/src/utf8.h
                       libshared/src/wcwidth6.cpp)

find_package(Threads REQUIRED)
add_executable (taskd_executable taskd.cpp)

target_link_libraries (taskd_executable taskd libshared ${TASKD_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

set_property (TARGET taskd_executable PROPERTY OUTPUT_NAME "taskd")

install (TARGETS taskd_executable DESTINATION ${TASKD_BINDIR})

