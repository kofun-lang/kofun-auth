cmake_minimum_required(VERSION 3.24)

project(kofun_auth VERSION 0.1.0 LANGUAGES C)

include(CTest)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

add_library(kofun_auth STATIC
  src/oauth.c
)
add_library(kofun::auth ALIAS kofun_auth)
target_compile_features(kofun_auth PUBLIC c_std_11)
target_include_directories(kofun_auth
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(kofun_auth PUBLIC OpenSSL::Crypto)

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(kofun_auth PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
  target_compile_options(kofun_auth PRIVATE /W4 /std:c11)
endif()

if(BUILD_TESTING)
  add_executable(oauth_test tests/oauth_test.c)
  target_link_libraries(oauth_test PRIVATE kofun::auth)
  add_test(NAME oauth_pkce_state_machine COMMAND oauth_test)

  try_compile(KOFUN_AUTH_PUBLIC_CLIENT_COMPILES
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tests/compile_pass/public_client.c
    CMAKE_FLAGS
      "-DINCLUDE_DIRECTORIES=${CMAKE_CURRENT_SOURCE_DIR}/include"
    OUTPUT_VARIABLE KOFUN_AUTH_PUBLIC_CLIENT_LOG
  )
  if(NOT KOFUN_AUTH_PUBLIC_CLIENT_COMPILES)
    message(FATAL_ERROR
      "The public client contract did not compile:\n${KOFUN_AUTH_PUBLIC_CLIENT_LOG}")
  endif()

  try_compile(KOFUN_AUTH_ACCEPTED_PUBLIC_SECRET
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tests/compile_fail/public_secret.c
    CMAKE_FLAGS
      "-DINCLUDE_DIRECTORIES=${CMAKE_CURRENT_SOURCE_DIR}/include"
    OUTPUT_VARIABLE KOFUN_AUTH_PUBLIC_SECRET_LOG
  )
  if(KOFUN_AUTH_ACCEPTED_PUBLIC_SECRET)
    message(FATAL_ERROR
      "A public client accepted a client_secret field:\n${KOFUN_AUTH_PUBLIC_SECRET_LOG}")
  endif()

  try_compile(KOFUN_AUTH_EXPOSED_PENDING_LAYOUT
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tests/compile_fail/pending_layout.c
    CMAKE_FLAGS
      "-DINCLUDE_DIRECTORIES=${CMAKE_CURRENT_SOURCE_DIR}/include"
    OUTPUT_VARIABLE KOFUN_AUTH_PENDING_LAYOUT_LOG
  )
  if(KOFUN_AUTH_EXPOSED_PENDING_LAYOUT)
    message(FATAL_ERROR
      "KofunAuthPending is constructible outside the library:\n${KOFUN_AUTH_PENDING_LAYOUT_LOG}")
  endif()
endif()
