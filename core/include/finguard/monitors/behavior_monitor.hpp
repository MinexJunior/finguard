#pragma once

#include "finguard/hal/platform_collector.hpp"
#include "finguard/types.hpp"
#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace finguard::monitors {

enum class SocketProtocol {
    TCP,
    UDP
};

enum class SocketState {
    Unknown,
    Listening,
    Established,
    CloseWait,
    TimeWait
};

struct NetworkSocketInfo {
    uint32_t pid{0};
    SocketProtocol protocol{SocketProtocol::TCP};
    SocketState state{SocketState::Established};
    std::string local_address;
    uint16_t local_port{0};
    std::string remote_address;
    uint16_t remote_port{0};
};

struct GlobalHookInfo {
    uint32_t pid{0};
    std::string process_name;
    int hook_type{0}; // e.g. WH_KEYBOARD (2), WH_KEYBOARD_LL (13)
    std::string hook_type_name;
    bool is_global{true};
};

struct BehaviorFinding {
    uint32_t pid{0};
    std::string process_name;
    std::string category; // "SuspiciousNetworkSocket", "RemoteDesktopCoPresence", "GlobalInputHook"
    Severity severity{Severity::High};
    uint32_t risk_weight{35};
    std::string title;
    std::string description;
    std::string observed_context;
};

struct BehaviorReport {
    std::vector<BehaviorFinding> findings;
    std::vector<NetworkSocketInfo> active_sockets;
    std::vector<GlobalHookInfo> installed_hooks;
    std::vector<std::string> active_remote_desktop_tools;
    bool has_active_remote_desktop{false};
    bool has_active_keylogger_hook{false};
};

class BehaviorMonitor {
public:
    explicit BehaviorMonitor(std::shared_ptr<hal::PlatformCollector> collector);
    ~BehaviorMonitor() = default;

    // Run complete behavioral audit
    BehaviorReport audit_behavior();

    // Specific behavioral inspectors
    std::vector<NetworkSocketInfo> enumerate_network_sockets();
    std::vector<BehaviorFinding> inspect_sockets(const std::vector<NetworkSocketInfo>& sockets,
                                                const std::vector<ProcessInfo>& processes);
    std::vector<BehaviorFinding> check_remote_desktop_presence(const std::vector<ProcessInfo>& processes);
    std::vector<BehaviorFinding> check_cross_process_access(const std::vector<ProcessInfo>& processes);
    std::vector<BehaviorFinding> check_global_hooks();

    // Helpers
    static bool is_known_remote_desktop_tool(const std::string& process_name);
    static bool is_suspicious_socket_binary(const std::string& process_name);
    static bool is_suspicious_remote_port(uint16_t port);

private:
    std::shared_ptr<hal::PlatformCollector> collector_;
};

} // namespace finguard::monitors
