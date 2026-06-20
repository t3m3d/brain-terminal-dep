// Windows ConPTY backend for brain-terminal.
//
// Uses Win10 1809+ pseudoconsole API (CreatePseudoConsole, ResizePseudoConsole,
// ClosePseudoConsole) attached to a child process via STARTUPINFOEXW with the
// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE_HANDLE thread attribute.
//
// Because ConPTY needs separate input + output pipes plus an HPCON plus the
// child PROCESS_INFORMATION — none of which fit the cross-platform `int
// masterFd` abstraction — we keep a process-wide std::unordered_map keyed by
// an integer "token". The token is what we hand back as `PTYHandles.masterFd`.
// All read/write/resize/close calls go through PTYPlatform's static methods
// which look up the real handles in the map.
//
// Krypton integration spot:
//   The default shell is "cmd.exe" today. Pointing this at a Krypton-built
//   shell ("C:\krypton\kr.exe" for the REPL, or any .ks script the user
//   chose in their config) is a one-line change once the cross-platform
//   Config layer exposes a "shell" field. See brain::Config TODOs.

// ConPTY (CreatePseudoConsole / ResizePseudoConsole / ClosePseudoConsole)
// was added in Windows 10 1809 (build 17763). Pin both _WIN32_WINNT and
// NTDDI_VERSION to that target before any system header lands so the
// pseudoconsole prototypes + the PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE_HANDLE
// attribute id are actually declared.
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000005   // NTDDI_WIN10_RS5
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

// MinGW's bundled mingw-w64 headers historically lag the Windows 10 SDK
// on ConPTY. Even with _WIN32_WINNT pinned to 0x0A00 the prototypes for
// CreatePseudoConsole / ResizePseudoConsole / ClosePseudoConsole and
// the HPCON typedef + PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE_HANDLE id
// may not land. Forward-declare them by hand; the symbols live in
// kernel32.dll (already linked) so the link step finds them at load
// time regardless. MSVC ignores these (its <consoleapi.h> wins via
// the include order above).
#ifndef HPCON
typedef VOID* HPCON;
#endif
#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE_HANDLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE_HANDLE \
        ProcThreadAttributeValue(22, FALSE, TRUE, FALSE)
#endif
extern "C" {
    HRESULT WINAPI CreatePseudoConsole(COORD size, HANDLE hInput, HANDLE hOutput,
                                       DWORD dwFlags, HPCON* phPC);
    HRESULT WINAPI ResizePseudoConsole(HPCON hPC, COORD size);
    VOID    WINAPI ClosePseudoConsole(HPCON hPC);
}

#include <atomic>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "brain/pty/PTYPlatform.hpp"

using namespace brain::pty;

namespace {

struct WindowsPTY {
    HPCON  hPC          = nullptr;
    HANDLE childStdinW  = nullptr;   // we write to this; child reads it as stdin
    HANDLE childStdoutR = nullptr;   // we read from this; child wrote it as stdout
    PROCESS_INFORMATION pi {};
};

std::mutex                                g_mu;
std::unordered_map<long long, WindowsPTY> g_ptys;
std::atomic<long long>                    g_next_token{1};

// Build the heap-allocated lpAttributeList carrying
// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE_HANDLE.
LPPROC_THREAD_ATTRIBUTE_LIST buildAttributeList(HPCON hPC) {
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    if (size == 0) return nullptr;

    auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, size));
    if (!attrs) return nullptr;

    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &size)) {
        HeapFree(GetProcessHeap(), 0, attrs);
        return nullptr;
    }

    if (!UpdateProcThreadAttribute(
            attrs, 0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE_HANDLE,
            hPC, sizeof(HPCON),
            nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attrs);
        HeapFree(GetProcessHeap(), 0, attrs);
        return nullptr;
    }
    return attrs;
}

// "/bin/bash" → "cmd.exe". Anything that contains a backslash, drive letter,
// or whose FIRST whitespace-delimited token ends in .exe / .bat / .cmd is
// passed through unchanged (so `pwsh.exe -NoProfile` works).
bool looksWindowsPath(const std::string& s) {
    if (s.size() >= 2 && s[1] == ':')           return true; // drive letter
    if (s.find('\\') != std::string::npos)      return true;
    // Take the first token (before any space) for the suffix check so args
    // like `pwsh.exe -NoProfile` are recognised.
    std::size_t sp = s.find_first_of(" \t");
    std::string head = (sp == std::string::npos) ? s : s.substr(0, sp);
    auto ends_with = [&](const std::string& str, const char* suf) {
        std::size_t n = std::strlen(suf);
        return str.size() >= n && _stricmp(str.c_str() + str.size() - n, suf) == 0;
    };
    return ends_with(head, ".exe") || ends_with(head, ".bat") || ends_with(head, ".cmd");
}

// Tier-1 Krypton integration (see KRYPTON_INTEGRATION.md). If kr.exe is on
// PATH AND %APPDATA%\brain-terminal\setup.ks exists, run the script and
// take its LAST LINE of stdout as the shell command. Bail (return empty
// string) on any failure — the caller falls back to cmd.exe / the user's
// explicit shellPath argument.
std::string kryptonResolveShell() {
    wchar_t appdataW[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"APPDATA", appdataW, MAX_PATH) == 0) return {};

    std::wstring scriptW = std::wstring(appdataW) + L"\\brain-terminal\\setup.ks";
    DWORD attr = GetFileAttributesW(scriptW.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) return {};

    // Build `kr.exe "<scriptW>"` — let CreateProcess search PATH for kr.exe.
    std::wstring cmd = L"kr.exe \"" + scriptW + L"\"";
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(L'\0');

    HANDLE outR = nullptr, outW = nullptr;
    SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    if (!CreatePipe(&outR, &outW, &sa, 0)) return {};
    SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb         = sizeof(STARTUPINFOW);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = outW;
    si.hStdError  = outW;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(
        nullptr, cmdBuf.data(),
        nullptr, nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        nullptr, nullptr,
        &si, &pi);
    CloseHandle(outW);

    if (!ok) { CloseHandle(outR); return {}; }

    // Read child stdout fully (cap at 8 KB — the script just prints a path).
    std::string out;
    char buf[1024];
    DWORD got = 0;
    while (ReadFile(outR, buf, sizeof(buf), &got, nullptr) && got > 0 && out.size() < 8192) {
        out.append(buf, got);
    }
    CloseHandle(outR);

    // Reap the child with a short bound so a hung Krypton script can't
    // wedge terminal startup forever.
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    // Last non-empty line is the shell command.
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ' || out.back() == '\t'))
        out.pop_back();
    std::size_t nl = out.find_last_of("\r\n");
    std::string last = (nl == std::string::npos) ? out : out.substr(nl + 1);
    // Strip leading whitespace.
    std::size_t lead = last.find_first_not_of(" \t");
    if (lead == std::string::npos) return {};
    return last.substr(lead);
}

// Widen a UTF-8 std::string into a std::wstring via the Win32 converter.
// A raw `std::wstring(s.begin(), s.end())` widens byte-by-byte, mangling
// any multi-byte UTF-8 sequence (so Unicode paths break silently).
std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

// True iff `exe` resolves on the current PATH (and the App-Paths registry
// fallback that SearchPathW also consults).
bool exeOnPath(const wchar_t* exe) {
    wchar_t buf[MAX_PATH] = {0};
    DWORD got = SearchPathW(nullptr, exe, nullptr, MAX_PATH, buf, nullptr);
    return got > 0 && got < MAX_PATH;
}

std::wstring resolveShell(const std::string& shellPath) {
    // Honour an explicit Windows-looking shellPath the caller passed.
    if (looksWindowsPath(shellPath)) {
        return utf8ToWide(shellPath);
    }

    // Otherwise consult Krypton if the user has a setup.ks.
    std::string krShell = kryptonResolveShell();
    if (!krShell.empty()) {
        return utf8ToWide(krShell);
    }

    // No explicit preference and no Krypton script — pick the most modern
    // shell available. Order: PowerShell 7+ (pwsh.exe) → Windows PowerShell
    // 5.x (powershell.exe, always present on Win10+) → cmd.exe last-resort.
    // `-NoLogo` skips the multi-line copyright banner PowerShell prints
    // on launch so the first thing the user sees is a prompt.
    if (exeOnPath(L"pwsh.exe"))       return L"pwsh.exe -NoLogo";
    if (exeOnPath(L"powershell.exe")) return L"powershell.exe -NoLogo";
    return L"cmd.exe";
}

}  // namespace

PTYHandles PTYPlatform::createPTY(const std::string& shellPath, int cols, int rows) {
    PTYHandles handles;

    HANDLE inputReadSide   = nullptr;
    HANDLE inputWriteSide  = nullptr;
    HANDLE outputReadSide  = nullptr;
    HANDLE outputWriteSide = nullptr;

    SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };

    if (!CreatePipe(&inputReadSide,  &inputWriteSide,  &sa, 0)) return handles;
    if (!CreatePipe(&outputReadSide, &outputWriteSide, &sa, 0)) {
        CloseHandle(inputReadSide);
        CloseHandle(inputWriteSide);
        return handles;
    }

    COORD size;
    size.X = static_cast<SHORT>(cols);
    size.Y = static_cast<SHORT>(rows);

    HPCON hPC = nullptr;
    HRESULT hr = CreatePseudoConsole(size, inputReadSide, outputWriteSide, 0, &hPC);
    // The pseudoconsole takes its own references to the ends it owns; release
    // our copies so closing the pty later actually shuts the pipes.
    CloseHandle(inputReadSide);
    CloseHandle(outputWriteSide);
    if (FAILED(hr)) {
        CloseHandle(inputWriteSide);
        CloseHandle(outputReadSide);
        return handles;
    }

    LPPROC_THREAD_ATTRIBUTE_LIST attrs = buildAttributeList(hPC);
    if (!attrs) {
        ClosePseudoConsole(hPC);
        CloseHandle(inputWriteSide);
        CloseHandle(outputReadSide);
        return handles;
    }

    STARTUPINFOEXW si{};
    si.StartupInfo.cb       = sizeof(STARTUPINFOEXW);
    si.lpAttributeList      = attrs;
    si.StartupInfo.dwFlags |= EXTENDED_STARTUPINFO_PRESENT;

    std::wstring cmdLine = resolveShell(shellPath);
    // CreateProcessW requires a writeable buffer for the command line.
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    // Launch the child in the user's home directory (USERPROFILE on
    // Windows) so opening brain.exe from anywhere — Start menu, desktop
    // shortcut, double-click — drops the user at `~` instead of
    // wherever the .exe was launched from. Fall back to the launcher's
    // CWD if USERPROFILE isn't set (unusual).
    wchar_t homeW[MAX_PATH] = {0};
    LPCWSTR lpCurrentDir = nullptr;
    if (GetEnvironmentVariableW(L"USERPROFILE", homeW, MAX_PATH) > 0) {
        lpCurrentDir = homeW;
    }

    // Custom environment block so terminal-detectors (kryofetch, neofetch,
    // fastfetch, etc.) identify brain instead of inheriting WT_SESSION /
    // ConEmuPID from whatever shell launched us. Start from the parent's
    // env, strip the known detection vars, then append our own.
    auto buildEnvBlock = []() -> std::vector<wchar_t> {
        LPWCH parent = GetEnvironmentStringsW();
        if (!parent) return {};

        std::vector<wchar_t> out;
        out.reserve(8192);

        // The strings that confuse detectors (case-insensitive prefix match).
        // Stripping them = the child sees brain as the host, not the parent
        // shell brain.exe was launched from.
        static const wchar_t* drop_prefixes[] = {
            L"WT_SESSION=",
            L"WT_PROFILE_ID=",
            L"ConEmuPID=",
            L"ConEmuANSI=",
            L"ConEmuDir=",
            L"TERM_PROGRAM=",
            L"TERM_PROGRAM_VERSION=",
            L"TERMINAL_EMULATOR=",
            L"TERMUX_VERSION=",
            L"VTE_VERSION=",
            L"KITTY_WINDOW_ID=",
            L"ALACRITTY_LOG=",
            L"GHOSTTY_RESOURCES_DIR=",
        };
        auto starts_with_ci = [](const wchar_t* s, const wchar_t* prefix) {
            while (*prefix) {
                wchar_t a = *s++;
                wchar_t b = *prefix++;
                if (a >= L'A' && a <= L'Z') a = (wchar_t)(a + 32);
                if (b >= L'A' && b <= L'Z') b = (wchar_t)(b + 32);
                if (a != b) return false;
            }
            return true;
        };

        for (LPWCH p = parent; *p; ) {
            bool drop = false;
            for (auto pfx : drop_prefixes) {
                if (starts_with_ci(p, pfx)) { drop = true; break; }
            }
            std::size_t len = wcslen(p);
            if (!drop) {
                out.insert(out.end(), p, p + len);
                out.push_back(L'\0');
            }
            p += len + 1;
        }
        FreeEnvironmentStringsW(parent);

        // Append brain's own identification.
        auto push_var = [&](const wchar_t* kv) {
            std::size_t n = wcslen(kv);
            out.insert(out.end(), kv, kv + n);
            out.push_back(L'\0');
        };
        push_var(L"TERM_PROGRAM=brain");
        push_var(L"TERM_PROGRAM_VERSION=0.1.0");
        push_var(L"TERMINAL_EMULATOR=brain");
        // TERM controls ANSI capabilities. xterm-256color is the broadly-
        // supported lingua franca for modern terminals.
        push_var(L"TERM=xterm-256color");
        push_var(L"COLORTERM=truecolor");

        // Double-null terminator.
        out.push_back(L'\0');
        return out;
    };
    std::vector<wchar_t> envBlock = buildEnvBlock();
    LPVOID lpEnvironment = envBlock.empty() ? nullptr : envBlock.data();

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(
        nullptr,
        cmdBuf.data(),
        nullptr, nullptr,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
        lpEnvironment, lpCurrentDir,
        &si.StartupInfo,
        &pi);

    DeleteProcThreadAttributeList(attrs);
    HeapFree(GetProcessHeap(), 0, attrs);

    if (!ok) {
        ClosePseudoConsole(hPC);
        CloseHandle(inputWriteSide);
        CloseHandle(outputReadSide);
        return handles;
    }

    WindowsPTY p;
    p.hPC          = hPC;
    p.childStdinW  = inputWriteSide;
    p.childStdoutR = outputReadSide;
    p.pi           = pi;

    long long token = g_next_token.fetch_add(1);
    {
        std::lock_guard<std::mutex> lk(g_mu);
        g_ptys.emplace(token, p);
    }

    handles.masterFd = token;
    handles.childPid = static_cast<long long>(pi.dwProcessId);
    return handles;
}

void PTYPlatform::resizePTY(long long masterFd, int cols, int rows) {
    HPCON hPC = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        auto it = g_ptys.find(masterFd);
        if (it == g_ptys.end()) return;
        hPC = it->second.hPC;
    }
    if (!hPC) return;
    COORD size;
    size.X = static_cast<SHORT>(cols);
    size.Y = static_cast<SHORT>(rows);
    ResizePseudoConsole(hPC, size);
}

long PTYPlatform::readData(long long masterFd, void* buffer, std::size_t bytes) {
    HANDLE h = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        auto it = g_ptys.find(masterFd);
        if (it == g_ptys.end()) return -1;
        h = it->second.childStdoutR;
    }
    if (!h) return -1;
    DWORD got = 0;
    BOOL ok = ReadFile(h, buffer, static_cast<DWORD>(bytes), &got, nullptr);
    if (!ok) {
        DWORD err = GetLastError();
        // Broken pipe = child exited; surface as EOF.
        if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF) return 0;
        return -1;
    }
    return static_cast<long>(got);
}

long PTYPlatform::writeData(long long masterFd, const void* buffer, std::size_t bytes) {
    HANDLE h = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        auto it = g_ptys.find(masterFd);
        if (it == g_ptys.end()) return -1;
        h = it->second.childStdinW;
    }
    if (!h) return -1;
    DWORD wrote = 0;
    if (!WriteFile(h, buffer, static_cast<DWORD>(bytes), &wrote, nullptr)) return -1;
    return static_cast<long>(wrote);
}

void PTYPlatform::closePTY(long long masterFd) {
    WindowsPTY p;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        auto it = g_ptys.find(masterFd);
        if (it == g_ptys.end()) return;
        p = it->second;
        g_ptys.erase(it);
    }

    if (p.hPC)          ClosePseudoConsole(p.hPC);
    if (p.childStdinW)  CloseHandle(p.childStdinW);
    if (p.childStdoutR) CloseHandle(p.childStdoutR);
    if (p.pi.hThread)   CloseHandle(p.pi.hThread);
    if (p.pi.hProcess)  CloseHandle(p.pi.hProcess);
}
