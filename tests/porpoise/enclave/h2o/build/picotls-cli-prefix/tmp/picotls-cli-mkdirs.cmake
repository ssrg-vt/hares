# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/deps/picotls"
  "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/build/picotls"
  "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/build/picotls-cli-prefix"
  "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/build/picotls-cli-prefix/tmp"
  "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/build/picotls-cli-prefix/src/picotls-cli-stamp"
  "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/build/picotls-cli-prefix/src"
  "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/build/picotls-cli-prefix/src/picotls-cli-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/build/picotls-cli-prefix/src/picotls-cli-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/abi/Drive/workspace/ssrg/ssrg/sgx_sample_applications/porpoise/enclave/h2o/build/picotls-cli-prefix/src/picotls-cli-stamp${cfgdir}") # cfgdir has leading slash
endif()
