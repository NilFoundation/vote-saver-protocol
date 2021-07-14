include(CMTest)
cm_find_package(Boost COMPONENTS unit_test_framework)
cm_test_link_libraries(
    crypto3::algebra
    crypto3::blueprint
    crypto3::fft
    crypto3::multiprecision
    crypto3::zk
${Boost_LIBRARIES})

cm_test(NAME circuit_test SOURCES circuit_test.cpp)
target_include_directories(circuit_test PRIVATE
"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
"$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

${Boost_INCLUDE_DIRS})

set_target_properties(circuit_test PROPERTIES CXX_STANDARD 14)
target_compile_definitions(circuit_test PRIVATE BOOST_TEST_DYN_LINK)
