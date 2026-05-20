cmake_minimum_required(VERSION 3.20)
project(win32tools VERSION 2.0.0 LANGUAGES CXX)

# ── Global settings ────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# ── Sources ────────────────────────────────────────────────────────────────────
set(W32T_TOOLS_SOURCES
    src/Tools/Core.cpp
    src/Tools/DriveInfo.cpp
    src/Tools/HaxHelper.cpp
    src/Tools/Inject.cpp
    "src/Tools/Scanner.cpp"
)

set(W32T_NETWORK_SOURCES
    src/Network/IocpTcpClient.cpp
    src/Network/IocpTcpServer.cpp
    src/Network/IocpUdpClient.cpp
    src/Network/IocpUdpServer.cpp
    src/Network/NamedPipe.cpp
    src/Network/NetworkSocket.cpp
    src/Network/Packet.cpp
    src/Network/Socket.cpp
)

# ── Library target ─────────────────────────────────────────────────────────────
add_library(${CMAKE_PROJECT_NAME} STATIC
    ${W32T_TOOLS_SOURCES}
    ${W32T_NETWORK_SOURCES}
)

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES
RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

target_include_directories(${CMAKE_PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(${CMAKE_PROJECT_NAME}
    PUBLIC
        ws2_32      # Winsock 2
        iphlpapi    # GetAdaptersInfo
        psapi       # GetModuleInformation
)

target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic -Werror>
)

target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# ── Install rules ──────────────────────────────────────────────────────────────
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/win32toolsConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/win32toolsConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/win32tools
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/win32toolsConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(TARGETS ${CMAKE_PROJECT_NAME}
    EXPORT  win32toolsTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT win32toolsTargets
    FILE      win32toolsTargets.cmake
    NAMESPACE w32t::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/win32tools
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/win32toolsConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/win32toolsConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/win32tools
)