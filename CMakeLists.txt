CMAKE_MINIMUM_REQUIRED(VERSION 3.5.1)

PROJECT(NTLM C)

IF (POLICY CMP0042)
    CMAKE_POLICY(SET CMP0042 NEW)
ENDIF()

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${NTLM_SOURCE_DIR}/cmake")

INCLUDE(AddCFlagIfSupported)
INCLUDE(EnableWarnings)
INCLUDE(FeatureSummary)

OPTION(BUILD_LIBRARY "Build the NTLM library" ON)
OPTION(BUILD_CLI     "Build the command-line interface" ON)
OPTION(BUILD_TESTS   "Build the test suite" ON)
OPTION(ENABLE_ASAN   "Enable AddressSanitizer" OFF)
OPTION(ENABLE_WERROR "Treat warnings as errors" ON)

SET(UNICODE "default" CACHE STRING "Unicode implementation to use; may be 'iconv' or 'builtin'.")
SET(CRYPT   "default" CACHE STRING "Cryptographic implementation to use; may be 'commoncrypto', 'mbedtls', 'openssl', or 'openssl-dynamic'.")

SET(PATH_SRC     "${NTLM_SOURCE_DIR}/src")
SET(PATH_INCLUDE "${NTLM_SOURCE_DIR}/include")
SET(PATH_CLI     "${NTLM_SOURCE_DIR}/cli")
SET(PATH_TESTS   "${NTLM_SOURCE_DIR}/tests")

# Default to iconv support if available; fallback to builtin conversion
IF(UNICODE STREQUAL "default")
	FIND_PACKAGE(Iconv)

	IF(ICONV_FOUND)
		SET(UNICODE "iconv")
	ELSE()
		SET(UNICODE "builtin")
	ENDIF()
ENDIF()

# Set up the unicode libraries
IF(UNICODE STREQUAL "iconv")
	FIND_PACKAGE(Iconv)

	IF(NOT ICONV_FOUND)
		MESSAGE(FATAL_ERROR "iconv support was not found")
	ENDIF()

	ADD_DEFINITIONS(-DUNICODE_ICONV)
	FILE(GLOB NTLM_SRC_UNICODE "${PATH_SRC}/unicode_iconv.c")

	LIST(APPEND NTLM_INCLUDES ${ICONV_INCLUDE_DIR})
	LIST(APPEND NTLM_LIBS ${ICONV_LIBRARIES})
	LIST(APPEND NTLM_PC_LIBS ${ICONV_LIBRARIES})

	ADD_FEATURE_INFO(UNICODE ON "using system iconv libraries")
ELSEIF(UNICODE STREQUAL "builtin")
	ADD_DEFINITIONS(-DUNICODE_BUILTIN)
	FILE(GLOB NTLM_SRC_UNICODE "${PATH_SRC}/unicode_builtin.c")

	ADD_FEATURE_INFO(UNICODE ON "using builtin Unicode conversion support")
ELSE()
	MESSAGE(FATAL_ERROR "invalid unicode support requested: ${UNICODE}")
ENDIF()

# Locate crypto support: default to CommonCrypto on macOS, use openssl
# otherwise.
IF(CRYPT STREQUAL "default")
	IF(APPLE)
		SET(CRYPT "commoncrypto")
	ELSE()
		FIND_PACKAGE(mbedTLS)
		FIND_PACKAGE(OpenSSL)

		IF(MBEDTLS_FOUND)
			SET(CRYPT "mbedtls")
		ELSEIF(OPENSSL_FOUND)
			SET(CRYPT "openssl")
		ELSE()
			MESSAGE(FATAL_ERROR "could not locate cryptographic libraries; install OpenSSL or mbedTLS")
		ENDIF()
	ENDIF()
ENDIF()

IF(CRYPT STREQUAL "commoncrypto")
	ADD_DEFINITIONS(-DCRYPT_COMMONCRYPTO)
	FILE(GLOB NTLM_SRC_CRYPT "${PATH_SRC}/crypt_commoncrypto.c")

	# CC_MD4 has been deprecated in macOS 10.15.
	SET_SOURCE_FILES_PROPERTIES("${PATH_SRC}/crypt_commoncrypto.c" COMPILE_FLAGS "-Wno-deprecated")

	ADD_FEATURE_INFO(CRYPT ON "using macOS CommonCrypto support")
ELSEIF(CRYPT STREQUAL "mbedtls")
	FIND_PACKAGE(mbedTLS)

	IF(NOT MBEDTLS_FOUND)
		MESSAGE(FATAL_ERROR "mbedTLS support was not found.  Please install the necessary mbedTLS development libraries.")
	ENDIF()

	ADD_DEFINITIONS(-DCRYPT_MBEDTLS)
	FILE(GLOB NTLM_SRC_CRYPT "${PATH_SRC}/crypt_mbedtls.c" "${PATH_SRC}/crypt_builtin_md4.c")

	LIST(APPEND NTLM_INCLUDES ${MBEDTLS_INCLUDE_DIR})
	LIST(APPEND NTLM_LIBS ${MBEDTLS_LIBRARIES})
	LIST(APPEND NTLM_PC_LIBS ${MBEDTLS_LIBRARIES})

	ADD_FEATURE_INFO(CRYPT ON "using mbedTLS")
ELSEIF(CRYPT STREQUAL "openssl")
	FIND_PACKAGE(OpenSSL)

	IF(NOT OPENSSL_FOUND)
		MESSAGE(FATAL_ERROR "OpenSSL support was not found.  Please install the necessary OpenSSL development libraries.")
	ENDIF()

	ADD_DEFINITIONS(-DCRYPT_OPENSSL)
	FILE(GLOB NTLM_SRC_CRYPT "${PATH_SRC}/crypt_openssl.c")

	LIST(APPEND NTLM_INCLUDES ${OPENSSL_INCLUDE_DIR})
	LIST(APPEND NTLM_LIBS ${OPENSSL_LIBRARIES})
	LIST(APPEND NTLM_PC_LIBS ${OPENSSL_LIBRARIES})

	ADD_FEATURE_INFO(CRYPT ON "using OpenSSL")
ELSEIF(CRYPT STREQUAL "openssl-dynamic")
	ADD_DEFINITIONS(-DCRYPT_OPENSSL)
	ADD_DEFINITIONS(-DCRYPT_OPENSSL_DYNAMIC)
	FILE(GLOB NTLM_SRC_CRYPT "${PATH_SRC}/crypt_openssl.c")

	LIST(APPEND NTLM_LIBS dl)

	ADD_FEATURE_INFO(CRYPT ON "using OpenSSL (dynamic)")
ELSE()
	MESSAGE(FATAL_ERROR "invalid cryptographic support requested: ${CRYPT}")
ENDIF()

SET(CMAKE_C_FLAGS "-std=gnu99 -D_DEFAULT_SOURCE")

ENABLE_WARNINGS(all)
ENABLE_WARNINGS(extra)
ENABLE_WARNINGS(documentation)
ENABLE_WARNINGS(missing-field-initializers)
ENABLE_WARNINGS(strict-aliasing=2)
ENABLE_WARNINGS(strict-prototypes)
ENABLE_WARNINGS(declaration-after-statement)
ENABLE_WARNINGS(shift-count-overflow)
ENABLE_WARNINGS(unused-const-variable)
ENABLE_WARNINGS(unused-function)
ENABLE_WARNINGS(format)
ENABLE_WARNINGS(int-conversion)
DISABLE_WARNINGS(implicit-fallthrough)

IF(ENABLE_ASAN)
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -ggdb")
	ADD_FEATURE_INFO(ENABLE_ASAN ON "AddressSanitizer is enabled")
ENDIF()

IF(NOT CMAKE_CONFIGURATION_TYPES)
	IF (NOT CMAKE_BUILD_TYPE)
		SET(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Type of build: Debug, Release, RelWithDebInfo, MinSizeRel.  Default is Debug." FORCE)
    ENDIF()
ENDIF()

FEATURE_SUMMARY(WHAT ENABLED_FEATURES DESCRIPTION "Configuration summary:")


# Parse the version number
FILE(STRINGS "${PATH_INCLUDE}/ntlmclient.h" NTLM_HEADER_VERSION REGEX "^#define NTLM_CLIENT_VERSION[\\t ]+")
STRING(REGEX REPLACE "^#define NTLM_CLIENT_VERSION[\\t ]+\"(.*)\".*$" "\\1" NTLM_VERSION "${NTLM_HEADER_VERSION}")

FILE(STRINGS "${PATH_INCLUDE}/ntlmclient.h" NTLM_HEADER_MAJOR REGEX "^#define NTLM_CLIENT_VERSION_MAJOR[\\t ]+")
STRING(REGEX REPLACE "^#define NTLM_CLIENT_VERSION_MAJOR[\\t ]+([0-9]+).*$" "\\1" NTLM_SOVERSION "${NTLM_HEADER_MAJOR}")


# Set up the build targets
FILE(GLOB NTLM_SRC_COMMON "${PATH_SRC}/ntlm.c" "${PATH_SRC}/util.c")
SET(NTLM_SRC ${NTLM_SRC_COMMON} ${NTLM_SRC_CRYPT} ${NTLM_SRC_UNICODE})

IF(BUILD_LIBRARY)
	INCLUDE_DIRECTORIES(${PATH_SRC} ${PATH_INCLUDE})
	ADD_LIBRARY(ntlmclient OBJECT ${NTLM_SRC})
	SET_PROPERTY(TARGET ntlmclient PROPERTY POSITION_INDEPENDENT_CODE 1)

	ADD_LIBRARY(ntlmclient_shared SHARED $<TARGET_OBJECTS:ntlmclient>)
	SET_TARGET_PROPERTIES(ntlmclient_shared PROPERTIES OUTPUT_NAME ntlmclient)
	SET_TARGET_PROPERTIES(ntlmclient_shared PROPERTIES VERSION ${NTLM_VERSION})
	SET_TARGET_PROPERTIES(ntlmclient_shared PROPERTIES SOVERSION ${NTLM_SOVERSION})
	TARGET_LINK_LIBRARIES(ntlmclient_shared ${NTLM_LIBS})

	ADD_LIBRARY(ntlmclient_static STATIC $<TARGET_OBJECTS:ntlmclient>)
	SET_TARGET_PROPERTIES(ntlmclient_static PROPERTIES OUTPUT_NAME ntlmclient)
	TARGET_LINK_LIBRARIES(ntlmclient_static ${NTLM_LIBS})

	TARGET_INCLUDE_DIRECTORIES(ntlmclient
		PRIVATE ${NTLM_INCLUDES}
		PUBLIC "${NTLM_SOURCE_DIR}/include")
ENDIF()

IF(BUILD_TESTS)
	SET(Python_ADDITIONAL_VERSIONS 3 2.7)
	FIND_PACKAGE(PythonInterp)

	FILE(GLOB NTLM_TEST "${PATH_TESTS}/*.c")

	ADD_CUSTOM_COMMAND(
		OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/clar.suite"
		COMMAND ${PYTHON_EXECUTABLE} ./generate.py -o "${CMAKE_CURRENT_BINARY_DIR}" .
		DEPENDS ${NTLM_SRC} ${NTLM_TEST}
		WORKING_DIRECTORY ${PATH_TESTS})

	SET_SOURCE_FILES_PROPERTIES(${PATH_TESTS}/clar.c
		PROPERTIES OBJECT_DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/clar.suite")

	INCLUDE_DIRECTORIES(${PATH_SRC} ${PATH_INCLUDE} ${PATH_TESTS}
		${CMAKE_CURRENT_BINARY_DIR}
		${NTLM_INCLUDES})

	ADD_EXECUTABLE(ntlm_tests ${NTLM_SRC} ${NTLM_TEST})
	TARGET_LINK_LIBRARIES(ntlm_tests ${NTLM_LIBS})
ENDIF()

IF(BUILD_CLI)
	FILE(GLOB NTLM_CLI "${PATH_CLI}/*.c")

	ADD_EXECUTABLE(ntlm ${NTLM_CLI})
	TARGET_LINK_LIBRARIES(ntlm ntlmclient_static ${NTLM_LIBS})
ENDIF()

ENABLE_TESTING()
ADD_TEST(full "${CMAKE_CURRENT_BINARY_DIR}/ntlm_tests" -v)
