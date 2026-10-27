# Core library
add_library(finguard_core STATIC
    src/hal/win32_collector.cpp
    src/hal/mock_collector.cpp
    src/monitors/process_monitor.cpp
    src/pe/entropy.cpp
    src/pe/signature_verifier.cpp
    src/pe/sha256.cpp
    src/pe/pe_analyzer.cpp
    src/monitors/permission_monitor.cpp
    src/monitors/behavior_monitor.cpp
    src/engine/risk_engine.cpp
    src/core_api.cpp
)

set_target_properties(finguard_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(finguard_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if (WIN32)
    target_link_libraries(finguard_core PUBLIC
        wintrust
        crypt32
        iphlpapi
        ws2_32
    )
endif()

# Shared dynamic library for C-ABI / Python bindings
add_library(finguard SHARED
    src/core_api.cpp
)
target_include_directories(finguard PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(finguard PRIVATE
    finguard_core
)

# Standalone CLI / Daemon executable
add_executable(finguard-core
    src/main.cpp
)

target_link_libraries(finguard-core PRIVATE
    finguard_core
)
