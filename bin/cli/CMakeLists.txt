cmake_minimum_required(VERSION 3.5)

cm_find_package(CM)
include(CMDeploy)
include(CMSetupVersion)

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    cm_project(devote WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES ASM C CXX)
else()
cm_project(cli WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES ASM C CXX)
endif()

if(NOT CMAKE_CROSSCOMPILING)
    cm_find_package(Boost COMPONENTS filesystem log log_setup program_options thread system)
elseif(CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    if(NOT TARGET boost)
        include(ExternalProject)
        set(Boost_LIBRARIES boost_random)
        externalproject_add(boost
                            PREFIX ${CMAKE_BINARY_DIR}/libs/boost
                            GIT_REPOSITORY git@github.com:boostorg/boost.git
                            GIT_TAG boost-1.77.0
                            BUILD_IN_SOURCE TRUE
                            CMAKE_ARGS -DCMAKE_CROSSCOMPILING_EMULATOR=${CMAKE_CROSSCOMPILING_EMULATOR} -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
                            BUILD_COMMAND cmake --build . --target ${Boost_LIBRARIES}
                            INSTALL_COMMAND "")
    else()
        set(Boost_LIBRARIES boost_random)
    endif()
elseif(CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_NAME STREQUAL "Android")
    set(Boost_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/../boost/${ANDROID_ABI}/include/boost-1_78")
    set(Boost_LIBRARIES ${CMAKE_SOURCE_DIR}/../boost/${ANDROID_ABI}/lib/libboost_random.a)
    find_library(log-lib log)
    list(APPEND PLATFORM_SPECIFIC_LIBRARIES ${log-lib})
endif()

cm_setup_version(VERSION 0.1.0)

# get header files; only needed by CMake generators,
# e.g., for creating proper Xcode projects
set(${CURRENT_PROJECT_NAME}_HEADERS)

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
            src/android.cpp)

    add_library(${CURRENT_PROJECT_NAME}
            SHARED
            ${${CURRENT_PROJECT_NAME}_HEADERS}
            ${${CURRENT_PROJECT_NAME}_SOURCES})
elseif(CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
            src/wasm.cpp)

    add_executable(${CURRENT_PROJECT_NAME}
            ${${CURRENT_PROJECT_NAME}_HEADERS}
            ${${CURRENT_PROJECT_NAME}_SOURCES})
else()
list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
     src/main.cpp)

add_executable(${CURRENT_PROJECT_NAME}
               ${${CURRENT_PROJECT_NAME}_HEADERS}
               ${${CURRENT_PROJECT_NAME}_SOURCES})
endif()

set_target_properties(${CURRENT_PROJECT_NAME} PROPERTIES
                      LINKER_LANGUAGE CXX
                      EXPORT_NAME ${CURRENT_PROJECT_NAME}
                      CXX_STANDARD 17
                      CXX_STANDARD_REQUIRED TRUE)

target_link_libraries(${CURRENT_PROJECT_NAME}

                      crypto3::algebra
                      crypto3::blueprint
                      crypto3::math
                      crypto3::multiprecision
                      crypto3::zk
                      crypto3::pubkey

                      marshalling::core
                      marshalling::crypto3_multiprecision
                      marshalling::crypto3_algebra
                      marshalling::crypto3_zk

                      ${Boost_LIBRARIES}

                      ${PLATFORM_SPECIFIC_LIBRARIES})

target_include_directories(${CURRENT_PROJECT_NAME} PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>

                           ${Boost_INCLUDE_DIRS})

if(CMAKE_BUILD_TYPE=="Release")
    set(CMAKE_CXX_FLAGS "-O3")
endif()

if(APPLE OR NOT ${CMAKE_TARGET_ARCHITECTURE} STREQUAL ${CMAKE_HOST_SYSTEM_PROCESSOR})
    set_target_properties(${CURRENT_PROJECT_NAME} PROPERTIES
                          XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "${APPLE_CODE_SIGN_IDENTITY}"
                          XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "${CMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM}")
elseif(CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    set_target_properties(${CURRENT_PROJECT_NAME} PROPERTIES
                          COMPILE_FLAGS "-s USE_BOOST_HEADERS=1 --memoryprofiler"
                          LINK_FLAGS "-s USE_BOOST_HEADERS=1  --memoryprofiler -s EXPORTED_FUNCTIONS=_free,_generate_voter_keypair,_init_election,_admin_keygen,_generate_vote,_tally_votes,_verify_tally -s EXPORTED_RUNTIME_METHODS=ccall,cwrap -s LLD_REPORT_UNDEFINED -s ASSERTIONS=1 -s ALLOW_MEMORY_GROWTH=1"
                          LINK_DIRECTORIES "${CMAKE_BINARY_DIR}/libs/boost/src/boost/stage/lib")

    add_dependencies(${CURRENT_PROJECT_NAME} boost)
endif()
