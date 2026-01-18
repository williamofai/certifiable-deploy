##############################################################################
# certifiable-deploy CMakeLists.txt
#
# Deterministic model packaging and cryptographic attestation
# for safety-critical ML deployment.
#
# Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
# Licensed under GPL-3.0 or commercial license.
#
# @traceability CD-MATH-001, CD-STRUCT-001
##############################################################################

cmake_minimum_required(VERSION 3.10)

project(certifiable-deploy
    VERSION 1.0.0
    DESCRIPTION "Deterministic model packaging for safety-critical ML"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow -Wconversion -Wstrict-prototypes")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffp-contract=off")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-fast-math")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-common -O2")

include_directories(${PROJECT_SOURCE_DIR}/include)

set(AUDIT_SOURCES
    src/audit/sha256.c
    src/audit/domain_hash.c
)

set(ATTEST_SOURCES
    src/attest/merkle.c
    src/attest/attest.c
)

set(TARGET_SOURCES
    src/target/target.c
)

set(VERIFY_SOURCES
    src/verify/verify.c
)

set(BUNDLE_SOURCES
    src/bundle/path_normalize.c
    src/bundle/builder.c
    src/bundle/reader.c
)

set(MANIFEST_SOURCES
    src/manifest/jcs.c
    src/manifest/manifest.c
)

set(LOADER_SOURCES
    src/loader/loader.c
)

set(ALL_SOURCES
    ${AUDIT_SOURCES}
    ${ATTEST_SOURCES}
    ${TARGET_SOURCES}
    ${VERIFY_SOURCES}
    ${BUNDLE_SOURCES}
    ${MANIFEST_SOURCES}
    ${LOADER_SOURCES}
)

add_library(certifiable_deploy STATIC ${ALL_SOURCES})

target_include_directories(certifiable_deploy PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

enable_testing()

add_executable(test_audit
    tests/unit/test_audit.c
    ${AUDIT_SOURCES}
)
target_include_directories(test_audit PRIVATE ${PROJECT_SOURCE_DIR}/include)
add_test(NAME test_audit COMMAND test_audit)

add_executable(test_attest
    tests/unit/test_attest.c
    ${AUDIT_SOURCES}
    ${ATTEST_SOURCES}
)
target_include_directories(test_attest PRIVATE ${PROJECT_SOURCE_DIR}/include)
add_test(NAME test_attest COMMAND test_attest)

add_executable(test_target
    tests/unit/test_target.c
    ${TARGET_SOURCES}
)
target_include_directories(test_target PRIVATE ${PROJECT_SOURCE_DIR}/include)
add_test(NAME test_target COMMAND test_target)

add_executable(test_verify
    tests/unit/test_verify.c
    ${ALL_SOURCES}
)
target_include_directories(test_verify PRIVATE ${PROJECT_SOURCE_DIR}/include)
add_test(NAME test_verify COMMAND test_verify)

add_executable(test_bundle
    tests/unit/test_bundle.c
    ${BUNDLE_SOURCES}
)
target_include_directories(test_bundle PRIVATE ${PROJECT_SOURCE_DIR}/include)
add_test(NAME test_bundle COMMAND test_bundle)

add_executable(test_manifest
    tests/unit/test_manifest.c
    ${MANIFEST_SOURCES}
)
target_include_directories(test_manifest PRIVATE ${PROJECT_SOURCE_DIR}/include)
add_test(NAME test_manifest COMMAND test_manifest)

add_executable(test_loader
    tests/unit/test_loader.c
    ${ALL_SOURCES}
)
target_include_directories(test_loader PRIVATE ${PROJECT_SOURCE_DIR}/include)
add_test(NAME test_loader COMMAND test_loader)

add_custom_target(test-all
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS test_audit test_attest test_target test_verify test_bundle test_manifest test_loader
    COMMENT "Running all certifiable-deploy tests"
)

add_custom_target(test-audit
    COMMAND test_audit
    DEPENDS test_audit
    COMMENT "Running audit tests"
)

add_custom_target(test-attest
    COMMAND test_attest
    DEPENDS test_attest
    COMMENT "Running attestation tests"
)

add_custom_target(test-target
    COMMAND test_target
    DEPENDS test_target
    COMMENT "Running target tests"
)

add_custom_target(test-verify
    COMMAND test_verify
    DEPENDS test_verify
    COMMENT "Running verification tests"
)

add_custom_target(test-bundle
    COMMAND test_bundle
    DEPENDS test_bundle
    COMMENT "Running bundle tests"
)

add_custom_target(test-manifest
    COMMAND test_manifest
    DEPENDS test_manifest
    COMMENT "Running manifest tests (SRS-004-MANIFEST)"
)

add_custom_target(test-loader
    COMMAND test_loader
    DEPENDS test_loader
    COMMENT "Running loader tests (SRS-006-LOADER)"
)

install(TARGETS certifiable_deploy
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

message(STATUS "")
message(STATUS "certifiable-deploy v${PROJECT_VERSION}")
message(STATUS "  C Standard:    C${CMAKE_C_STANDARD}")
message(STATUS "  Build Type:    ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler:      ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "")
