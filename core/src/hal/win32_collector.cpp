#include "finguard/hal/win32_collector.hpp"
#include <iostream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <sddl.h>

namespace finguard::hal {

static std::string wide_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), str.data(), size_needed, nullptr, nullptr);
    return str;
}

Win32Collector::Win32Collector() = default;
Win32Collector::~Win32Collector() = default;

std::vector<ProcessInfo> Win32Collector::enumerate_processes() {
    std::vector<ProcessInfo> processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            ProcessInfo info;
            info.pid = pe32.th32ProcessID;
            info.ppid = pe32.th32ParentProcessID;
            info.name = wide_to_utf8(pe32.szExeFile);

            // Attempt to get the full authentic path on disk
            HANDLE proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (proc_handle) {
                wchar_t path_buffer[MAX_PATH];
                DWORD path_size = MAX_PATH;
                if (QueryFullProcessImageNameW(proc_handle, 0, path_buffer, &path_size)) {
                    info.executable_path = wide_to_utf8(std::wstring(path_buffer, path_size));
                }

                query_token_info(proc_handle, info);
                CloseHandle(proc_handle);
            }

            processes.push_back(std::move(info));
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return processes;
}

std::optional<ProcessInfo> Win32Collector::get_process_by_pid(uint32_t pid) {
    auto all = enumerate_processes();
    for (auto& p : all) {
        if (p.pid == pid) {
            return p;
        }
    }
    return std::nullopt;
}

std::vector<ModuleInfo> Win32Collector::get_loaded_modules(uint32_t pid) {
    std::vector<ModuleInfo> modules;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return modules;
    }

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(snapshot, &me32)) {
        do {
            ModuleInfo m;
            m.name = wide_to_utf8(me32.szModule);
            m.path = wide_to_utf8(me32.szExePath);
            m.base_address = reinterpret_cast<uint64_t>(me32.modBaseAddr);
            m.module_size = me32.modBaseSize;
            modules.push_back(std::move(m));
        } while (Module32NextW(snapshot, &me32));
    }

    CloseHandle(snapshot);
    return modules;
}

std::vector<PrivilegeInfo> Win32Collector::get_process_privileges(uint32_t pid) {
    std::vector<PrivilegeInfo> privs;
    HANDLE proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc_handle) return privs;

    HANDLE token = nullptr;
    if (OpenProcessToken(proc_handle, TOKEN_QUERY, &token)) {
        DWORD len = 0;
        GetTokenInformation(token, TokenPrivileges, nullptr, 0, &len);
        if (len > 0) {
            std::vector<uint8_t> buffer(len);
            if (GetTokenInformation(token, TokenPrivileges, buffer.data(), len, &len)) {
                auto* tp = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.data());
                for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
                    wchar_t name_buf[256];
                    DWORD name_len = 256;
                    if (LookupPrivilegeNameW(nullptr, &tp->Privileges[i].Luid, name_buf, &name_len)) {
                        PrivilegeInfo priv;
                        priv.name = wide_to_utf8(std::wstring(name_buf, name_len));
                        priv.is_enabled = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                        privs.push_back(priv);
                    }
                }
            }
        }
        CloseHandle(token);
    }
    CloseHandle(proc_handle);
    return privs;
}

void Win32Collector::query_token_info(void* proc_handle, ProcessInfo& info) {
    HANDLE token = nullptr;
    if (OpenProcessToken(reinterpret_cast<HANDLE>(proc_handle), TOKEN_QUERY, &token)) {
        // Query Integrity Level
        DWORD len = 0;
        GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &len);
        if (len > 0) {
            std::vector<uint8_t> buf(len);
            if (GetTokenInformation(token, TokenIntegrityLevel, buf.data(), len, &len)) {
                auto* til = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
                DWORD sub_auth = *GetSidSubAuthority(til->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(til->Label.Sid)-1));
                if (sub_auth < SECURITY_MANDATORY_LOW_RID) {
                    info.integrity_level = IntegrityLevel::Untrusted;
                } else if (sub_auth < SECURITY_MANDATORY_MEDIUM_RID) {
                    info.integrity_level = IntegrityLevel::Low;
                } else if (sub_auth < SECURITY_MANDATORY_HIGH_RID) {
                    info.integrity_level = IntegrityLevel::Medium;
                } else if (sub_auth < SECURITY_MANDATORY_SYSTEM_RID) {
                    info.integrity_level = IntegrityLevel::High;
                    info.is_elevated = true;
                } else {
                    info.integrity_level = IntegrityLevel::System;
                    info.is_elevated = true;
                }
            }
        }
        CloseHandle(token);
    }
}

} // namespace finguard::hal

#else // Non-Windows implementation stub

namespace finguard::hal {

Win32Collector::Win32Collector() = default;
Win32Collector::~Win32Collector() = default;

std::vector<ProcessInfo> Win32Collector::enumerate_processes() {
    return {};
}

std::optional<ProcessInfo> Win32Collector::get_process_by_pid(uint32_t pid) {
    return std::nullopt;
}

std::vector<ModuleInfo> Win32Collector::get_loaded_modules(uint32_t pid) {
    return {};
}

std::vector<PrivilegeInfo> Win32Collector::get_process_privileges(uint32_t pid) {
    return {};
}

} // namespace finguard::hal

#endif
