##############################################################
# APCL – Activity-Proof Consensus Locking
#
# Include from the repository root CMakeLists.txt with:
#   include(apcl/CMakeLists_apcl.cmake)
#
# Adds three build targets:
#   apcl                       – shared library (the solution layer)
#   attack_double_spend_apcl   – targeted double-spend prevention demo
#   apcl_integration_tests     – full 10-scenario integration test suite
##############################################################

############################################################
# APCL shared library
############################################################
add_library(apcl SHARED
    ${PROJECT_SOURCE_DIR}/apcl/apcl.c
)
add_library(apcl::lib ALIAS apcl)

target_include_directories(apcl PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/apcl
)

target_link_libraries(apcl
    PUBLIC  lactxv2::library
    PRIVATE OpenSSL::SSL
    PRIVATE SQLite::SQLite3
    PRIVATE pthread
)

############################################################
# Double-spend prevention demo (mirrors original attack test)
############################################################
add_executable(attack_double_spend_apcl
    ${PROJECT_SOURCE_DIR}/apcl/attack_double_spend_apcl.c
)

target_include_directories(attack_double_spend_apcl PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/apcl
)

target_link_libraries(attack_double_spend_apcl
    PRIVATE apcl::lib
    PRIVATE lactxv2::library
    PRIVATE OpenSSL::SSL
    PRIVATE SQLite::SQLite3
    PRIVATE pthread
)

############################################################
# Full integration test suite (10 scenarios)
############################################################
add_executable(apcl_integration_tests
    ${PROJECT_SOURCE_DIR}/apcl/apcl_integration_tests.c
)

target_include_directories(apcl_integration_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/apcl
)

target_link_libraries(apcl_integration_tests
    PRIVATE apcl::lib
    PRIVATE lactxv2::library
    PRIVATE OpenSSL::SSL
    PRIVATE SQLite::SQLite3
    PRIVATE pthread
)

############################################################
# CTest integration (optional: run via `ctest` in build dir)
############################################################
enable_testing()
add_test(NAME APCL_BasicTests   COMMAND attack_double_spend_apcl)
add_test(NAME APCL_FullSuite    COMMAND apcl_integration_tests)
