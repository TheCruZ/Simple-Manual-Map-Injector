cmake_minimum_required(VERSION 3.15)

project(TheCruZMMap)

set(SRC_ROOT "Manual Map Injector")

include(CBuildKit)

add_library_ns(thecruz manualmap STATIC ${SRC_ROOT}/injector.cpp)
target_include_dir_iface(thecruz-manualmap PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/${SRC_ROOT} include)
install_target_and_headers(thecruz manualmap)
target_compile_features(thecruz-manualmap PUBLIC cxx_std_17)

add_executable(injector ${SRC_ROOT}/main.cpp)
target_link_libraries(injector thecruz::manualmap)
target_compile_definitions(injector PRIVATE -DUNICODE -D_UNICODE)

install(FILES 
    ${SRC_ROOT}/injector.h
    DESTINATION include/TheCruZ)

configure_file(TheCruZMMapConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/TheCruZMMapConfig.cmake
    @ONLY)

# Realize Installation of Configuration cmake file
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/TheCruZMMapConfig.cmake
    DESTINATION lib/cmake/TheCruZ)