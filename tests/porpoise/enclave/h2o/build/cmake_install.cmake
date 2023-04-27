# Install script for directory: /home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/build/libh2o-evloop.a")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/h2o" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/h2o")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/h2o"
         RPATH "")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/build/h2o")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/h2o" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/h2o")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/h2o")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE DIRECTORY FILES "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/include/" FILES_MATCHING REGEX "/[^/]*\\.h$")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" TYPE FILE FILES "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/build/libh2o-evloop.pc")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/h2o" TYPE PROGRAM FILES
    "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/share/h2o/annotate-backtrace-symbols"
    "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/share/h2o/fastcgi-cgi"
    "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/share/h2o/fetch-ocsp-response"
    "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/share/h2o/kill-on-close"
    "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/share/h2o/setuidgid"
    "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/share/h2o/start_server"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/h2o" TYPE FILE FILES "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/share/h2o/ca-bundle.crt")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/h2o/status" TYPE FILE FILES "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/share/h2o/status/index.html")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/doc/h2o" TYPE DIRECTORY FILES "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/doc/" REGEX "/Makefile$" EXCLUDE REGEX "/h2o\\.8$" EXCLUDE REGEX "/README\\.md$" EXCLUDE)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/man/man8" TYPE FILE FILES "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/doc/h2o.8")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/man/man5" TYPE FILE FILES "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/doc/h2o.conf.5")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/doc/h2o/examples" TYPE DIRECTORY FILES "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/examples/")
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/build/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
