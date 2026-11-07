"""Turn an import table into capabilities.

Every imported API is matched against a small hand-written table that maps
module + function to a capability bucket ("network", "keyboard", "injection",
...). Patterns ending in ``*`` are prefixes (CreateFile* -> CreateFileW).
The first matching pattern inside a module wins.
"""

from __future__ import annotations

from typing import Any

# category -> (short human phrase, suspicion weight)
CATEGORY_INFO: dict[str, tuple[str, int]] = {
    "network": ("raw TCP/UDP sockets", 5),
    "http": ("HTTP client calls", 4),
    "download": ("downloads from URLs", 8),
    "dns": ("DNS lookups", 1),
    "netauth": ("network authentication (SSPI)", 3),
    "netinfo": ("reads network/adapter configuration", 2),
    "file": ("file system access", 1),
    "registry": ("registry access", 4),
    "process": ("process creation / handle access", 5),
    "thread": ("thread manipulation", 2),
    "injection": ("cross-process memory writes", 25),
    # Reading another process's memory is a *diagnostic* primitive: debuggers, crash
    # reporters, task manager. It cannot modify or execute anything, so it must not
    # share a bucket with WriteProcessMemory/CreateRemoteThread.
    "memory-read": ("reads another process's memory", 6),
    "service": ("service manager control", 16),
    "driver": ("kernel driver / device access", 20),
    "crypto": ("cryptographic primitives", 3),
    "dpapi": ("DPAPI secret protection", 10),
    "keyboard": ("keystroke state reads", 24),
    "hook": ("global Windows hooks", 18),
    "screen": ("screen/DC capture", 12),
    "input": ("synthetic keyboard/mouse input", 10),
    "clipboard": ("clipboard access", 3),
    "privilege": ("token / privilege manipulation", 8),
    "shell-exec": ("shell command execution", 10),
    "anti-debug": ("debugger detection", 6),
    "timing": ("high-resolution timing", 0),
    "enum": ("process/system enumeration", 3),
    "shadowcopy": ("volume shadow copy access", 14),
    "wifi": ("wireless profile access", 6),
    "audio": ("audio capture", 10),
    "com": ("COM runtime", 0),
    "ui": ("window/message loop", 0),
    "console": ("console I/O", 0),
    "python": ("embedded CPython runtime", 2),
    "crt": ("C runtime", 0),
    "runtime": ("OS/library glue (no specific capability)", 0),
    "netapi": ("SAM/share enumeration", 10),
}

# module name (lower-case, no .dll) -> ordered [(pattern, category)]
MODULES: dict[str, list[tuple[str, str]]] = {
    "ws2_32": [
        ("WSAStartup", "network"), ("WSACleanup", "network"), ("WSASocket*", "network"),
        ("socket", "network"), ("connect", "network"), ("bind", "network"),
        ("listen", "network"), ("accept", "network"), ("closesocket", "network"),
        ("send", "network"), ("sendto", "network"), ("recv", "network"),
        ("recvfrom", "network"), ("WSASend*", "network"), ("WSARecv*", "network"),
        ("select", "network"), ("ioctlsocket", "network"), ("WSAIoctl", "network"),
        ("getaddrinfo", "dns"), ("freeaddrinfo", "dns"), ("gethostbyname*", "dns"),
        ("gethostbyaddr", "dns"), ("getservbyname", "dns"),
        ("inet_addr", "network"), ("inet_ntoa", "network"), ("inet_pton", "network"),
        ("htons", "network"), ("ntohs", "network"), ("htonl", "network"),
        ("setsockopt", "network"), ("getsockopt", "network"), ("shutdown", "network"),
        ("getpeername", "network"), ("getsockname", "network"), ("WSAPoll", "network"),
    ],
    "wsock32": [("*", "network")],
    "mswsock": [("AcceptEx", "network"), ("ConnectEx", "network"), ("TransmitFile", "network")],
    "wininet": [
        ("InternetOpen*", "http"), ("InternetConnect*", "http"),
        ("HttpOpenRequest*", "http"), ("HttpSendRequest*", "http"),
        ("HttpQueryInfo*", "http"), ("InternetReadFile", "http"),
        ("InternetOpenUrl*", "download"), ("InternetQueryOption*", "http"),
        ("InternetSetOption*", "http"), ("InternetWriteFile", "http"),
        ("FtpPutFile", "download"), ("FtpOpenFile*", "download"),
        ("InternetCrackUrl*", "http"), ("InternetCloseHandle", "http"),
        ("InternetSetStatusCallback", "http"),
    ],
    "winhttp": [
        ("WinHttpOpen", "http"), ("WinHttpConnect", "http"),
        ("WinHttpOpenRequest", "http"), ("WinHttpSendRequest", "http"),
        ("WinHttpReceiveResponse", "http"), ("WinHttpReadData", "http"),
        ("WinHttpQueryHeaders", "http"), ("WinHttpSetOption", "http"),
        ("WinHttpCrackUrl", "http"), ("WinHttpWriteData", "http"),
        ("WinHttpGetIEProxyConfigForCurrentUser", "http"),
    ],
    "urlmon": [
        ("URLDownloadToFile*", "download"), ("URLDownloadToCacheFile*", "download"),
        ("ObtainUserAgentString", "http"), ("CoInternetGetSession", "http"),
        ("URLOpenStream*", "download"), ("URLDownloadToFileW", "download"),
    ],
    "dnsapi": [("DnsQuery*", "dns"), ("DnsFree", "dns"), ("DnsRecordListFree", "dns")],
    "iphlpapi": [
        ("GetAdaptersInfo", "netinfo"), ("GetAdaptersAddresses", "netinfo"),
        ("GetIpAddrTable", "netinfo"), ("GetTcpTable", "netinfo"),
        ("GetExtendedTcpTable", "netinfo"), ("GetUdpTable", "netinfo"),
        ("GetBestRoute", "netinfo"), ("NotifyAddrChange", "netinfo"),
        ("GetNetworkParams", "netinfo"), ("GetIfTable*", "netinfo"),
        ("GetIpNetTable", "netinfo"), ("SendARP", "netinfo"),
    ],
    "secur32": [
        ("AcquireCredentialsHandle*", "netauth"), ("InitializeSecurityContext*", "netauth"),
        ("QueryContextAttributes*", "netauth"), ("AcceptSecurityContext", "netauth"),
    ],
    "kernel32": [
        # "injection" is reserved for primitives that can *write* or *execute* inside
        # another process. Read-only access lives in "memory-read".
        ("VirtualAllocEx", "injection"), ("VirtualProtectEx", "injection"),
        ("WriteProcessMemory", "injection"), ("ReadProcessMemory", "memory-read"),
        ("CreateRemoteThread*", "injection"), ("QueueUserAPC", "injection"),
        ("SetThreadContext", "injection"), ("GetThreadContext", "memory-read"),
        ("CreateToolhelp32Snapshot", "enum"), ("Process32First*", "enum"),
        ("Process32Next*", "enum"), ("Module32First*", "enum"),
        ("Thread32First*", "enum"),
        ("IsDebuggerPresent", "anti-debug"),
        ("CheckRemoteDebuggerPresent", "anti-debug"),
        ("OutputDebugString*", "anti-debug"),
        ("QueryPerformanceCounter", "timing"), ("GetTickCount*", "timing"),
        ("CreateProcess*", "process"), ("OpenProcess", "process"),
        ("TerminateProcess", "process"), ("CreateThread", "thread"),
        ("OpenThread", "thread"), ("ResumeThread", "thread"), ("SuspendThread", "thread"),
        ("WinExec", "shell-exec"),
        ("CreateFile*", "file"), ("ReadFile*", "file"), ("WriteFile*", "file"),
        ("DeleteFile*", "file"), ("CopyFile*", "file"), ("MoveFile*", "file"),
        ("FindFirstFile*", "file"), ("FindNextFile*", "file"),
        ("GetTempPath*", "file"), ("GetTempFileName*", "file"),
        ("SetFileAttributes*", "file"), ("GetFileSize*", "file"),
        ("SetEndOfFile", "file"), ("CreateDirectory*", "file"),
        ("RemoveDirectory*", "file"), ("CreateFileMapping*", "file"),
        ("MapViewOfFile*", "file"), ("GetLogicalDrives", "file"),
        ("GetVolumeInformation*", "file"), ("FindFirstVolume*", "file"),
        ("DeviceIoControl", "driver"),
        ("LoadLibrary*", "com"), ("GetProcAddress", "com"),
        ("GetEnvironmentVariable*", "file"), ("GetComputerName*", "file"),
        ("GetUserName*", "file"),
        ("AdjustTokenPrivileges", "privilege"),
        ("GetStdHandle", "console"), ("WriteConsole*", "console"),
        ("AllocConsole", "console"),
    ],
    "ntdll": [
        # write/execute primitives only; NtReadVirtualMemory is a reader.
        ("NtWriteVirtualMemory", "injection"), ("NtReadVirtualMemory", "memory-read"),
        ("NtCreateThreadEx", "injection"), ("NtAllocateVirtualMemoryEx", "injection"),
        ("NtUnmapViewOfSection", "injection"), ("NtMapViewOfSection", "injection"),
        ("NtQueueApcThread", "injection"), ("NtSetContextThread", "injection"),
        ("RtlCreateUserThread", "injection"),
        ("NtQueryInformationProcess", "anti-debug"),
        ("NtSetInformationThread", "anti-debug"),
        ("NtQuerySystemInformation", "enum"),
        # "driver" means loading/unloading a kernel driver, not asking a device a
        # question (DeviceIoControl stays there as device access).
        ("NtLoadDriver", "driver"), ("ZwLoadDriver", "driver"),
        ("NtUnloadDriver", "driver"), ("ZwUnloadDriver", "driver"),
        ("NtOpenKey", "registry"), ("NtSetValueKey", "registry"),
        ("NtCreateKey", "registry"),
        ("NtQueryInformationFile", "file"), ("NtCreateFile", "file"),
    ],
    "advapi32": [
        ("OpenSCManager*", "service"), ("CreateService*", "service"),
        ("OpenService*", "service"), ("StartService*", "service"),
        ("ControlService*", "service"), ("DeleteService", "service"),
        ("ChangeServiceConfig*", "service"), ("QueryServiceStatus*", "service"),
        ("EnumServicesStatus*", "service"),
        ("StartServiceCtrlDispatcher*", "service"),
        ("RegisterServiceCtrlHandler*", "service"),
        ("RegOpenKey*", "registry"), ("RegCreateKey*", "registry"),
        ("RegSetValue*", "registry"), ("RegQueryValue*", "registry"),
        ("RegDeleteKey*", "registry"), ("RegDeleteValue*", "registry"),
        ("RegEnumKey*", "registry"), ("RegEnumValue*", "registry"),
        ("RegGetValue*", "registry"), ("RegSaveKey*", "registry"),
        ("RegLoadKey*", "registry"), ("RegRestoreKey*", "registry"),
        ("CryptProtectData", "dpapi"), ("CryptUnprotectData", "dpapi"),
        ("CryptAcquireContext*", "crypto"), ("CryptEncrypt", "crypto"),
        ("CryptDecrypt", "crypto"), ("CryptGenKey", "crypto"),
        ("CryptDeriveKey", "crypto"), ("CryptHashData", "crypto"),
        ("CryptImportKey", "crypto"), ("CryptExportKey", "crypto"),
        ("CryptCreateHash", "crypto"), ("CryptGenRandom", "crypto"),
        ("AdjustTokenPrivileges", "privilege"), ("OpenProcessToken", "privilege"),
        ("OpenThreadToken", "privilege"), ("DuplicateToken*", "privilege"),
        ("ImpersonateLoggedOnUser", "privilege"), ("RevertToSelf", "privilege"),
        ("LogonUser*", "privilege"), ("CreateProcessAsUser*", "privilege"),
        ("CreateProcessWithLogon*", "privilege"), ("CreateProcessWithToken*", "privilege"),
        ("LookupPrivilege*", "privilege"), ("GetTokenInformation", "privilege"),
        ("SetTokenInformation", "privilege"),
        ("InitializeSecurityDescriptor", "privilege"),
        ("InitializeAcl", "privilege"),
    ],
    "bcrypt": [("BCrypt*", "crypto")],
    "ncrypt": [("NCrypt*", "crypto")],
    "crypt32": [
        ("CryptStringToBinary*", "crypto"), ("CryptBinaryToString*", "crypto"),
        ("CryptDecodeObject*", "crypto"), ("CryptEncodeObject*", "crypto"),
        ("CertOpenStore", "crypto"), ("CertFindCertificateInStore", "crypto"),
        ("CryptProtectData", "dpapi"), ("CryptUnprotectData", "dpapi"),
        ("PFXImportCertStore", "crypto"),
    ],
    "cryptsp": [("Crypt*", "crypto")],
    "user32": [
        ("GetAsyncKeyState", "keyboard"), ("GetKeyState", "keyboard"),
        ("GetKeyboardState", "keyboard"), ("MapVirtualKey*", "keyboard"),
        ("ToUnicode*", "keyboard"), ("RegisterRawInputDevices", "keyboard"),
        ("GetRawInputData", "keyboard"),
        ("SetWindowsHookEx*", "hook"), ("UnhookWindowsHookEx", "hook"),
        ("CallNextHookEx", "hook"),
        ("keybd_event", "input"), ("mouse_event", "input"), ("SendInput", "input"),
        ("SetCursorPos", "input"), ("BlockInput", "input"),
        ("PrintWindow", "screen"), ("GetDC", "ui"), ("GetWindowDC", "ui"),
        ("FindWindow*", "ui"), ("GetForegroundWindow", "ui"),
        ("GetWindowText*", "ui"), ("MessageBox*", "ui"),
        ("CreateWindowEx*", "ui"), ("RegisterClass*", "ui"),
        ("OpenClipboard", "clipboard"), ("GetClipboardData", "clipboard"),
        ("SetClipboardData", "clipboard"), ("EmptyClipboard", "clipboard"),
    ],
    "gdi32": [
        ("BitBlt", "screen"), ("StretchBlt", "screen"), ("GetDIBits", "screen"),
        ("CreateCompatibleDC", "ui"), ("CreateCompatibleBitmap", "ui"),
        ("SelectObject", "ui"), ("CreateDIBSection", "ui"),
    ],
    "dwmapi": [("DwmGetWindowAttribute", "screen")],
    "shell32": [
        ("ShellExecute*", "shell-exec"), ("SHFileOperation*", "file"),
        ("SHGetKnownFolderPath", "file"), ("SHGetFolderPath*", "file"),
        ("CommandLineToArgvW", "shell-exec"), ("IsUserAnAdmin", "privilege"),
    ],
    "dbghelp": [("MiniDumpWriteDump", "memory-read"), ("SymInitialize*", "anti-debug")],
    "psapi": [("EnumProcesses", "enum"), ("EnumProcessModules*", "enum"),
              ("GetModuleInformation", "enum"), ("GetProcessMemoryInfo", "enum")],
    "wtsapi32": [("WTSEnumerateSessions*", "enum"), ("WTSQuerySessionInformation*", "enum")],
    "netapi32": [
        ("NetUserEnum", "netapi"), ("NetShareEnum", "netapi"),
        ("NetLocalGroupEnum", "netapi"), ("NetUserAdd", "netapi"),
        ("NetShareAdd", "netapi"),
    ],
    "vssapi": [("CreateVssBackupComponents*", "shadowcopy"),
               ("VssFreeSnapshotProperties", "shadowcopy")],
    "wlanapi": [("WlanOpenHandle", "wifi"), ("WlanEnumInterfaces", "wifi"),
                ("WlanGetAvailableNetworkList", "wifi"), ("WlanGetProfile*", "wifi"),
                ("WlanConnect", "wifi")],
    "winmm": [("waveIn*", "audio"), ("mciSendString*", "audio"),
              ("PlaySound*", "audio"), ("waveOutWrite", "audio")],
    "ole32": [("CoInitialize*", "com"), ("CoCreateInstance*", "com"),
              ("CoGetClassObject", "com"), ("CoTaskMemAlloc", "com")],
    "oleaut32": [("SysAllocString*", "com"), ("VariantInit", "com")],
    "combase": [("RoInitialize", "com")],
    # Enumerating device classes is discovery, not driver loading: Device Manager,
    # setup tools and hardware inventory all do it.
    "setupapi": [("SetupDiGetClassDevs*", "enum"), ("SetupDiEnumDeviceInfo", "enum")],
    "cfgmgr32": [("CM_Get_Device_ID*", "enum"), ("CM_Locate_DevNode*", "enum")],
}


def _normalize_module(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
    if base.endswith(".dll"):
        base = base[:-4]
    return base


def _match(table: list[tuple[str, str]], func: str) -> str | None:
    for pattern, category in table:
        if pattern.endswith("*"):
            if func.startswith(pattern[:-1]):
                return category
        elif func == pattern:
            return category
    return None


# A module that is imported at all already tells us something, which matters for
# binaries that import socket APIs by ordinal (curl does exactly that).
MODULE_DEFAULT = {
    "ws2_32": "network", "wsock32": "network", "mswsock": "network", "ws2help": "network",
    "wininet": "http", "winhttp": "http", "urlmon": "download",
    "dnsapi": "dns", "iphlpapi": "netinfo", "secur32": "netauth",
    "bcrypt": "crypto", "ncrypt": "crypto", "crypt32": "crypto", "cryptsp": "crypto",
    "dbghelp": "anti-debug", "psapi": "enum", "wtsapi32": "enum", "netapi32": "netapi",
    "vssapi": "shadowcopy", "wlanapi": "wifi", "winmm": "audio",
}

# Modules whose unmatched functions are OS/library glue rather than capability.
RUNTIME_MODULES = {    "kernel32", "kernelbase", "ntdll", "ucrtbase", "msvcrt", "msvcp140",
    "msvcp_win", "vcruntime140", "vcruntime140_1", "vccorlib140", "combase",
    "rpcrt4", "sechost", "advapi32", "user32", "gdi32", "ole32", "oleaut32",
    "shlwapi", "version", "winmm", "imm32", "uxtheme", "msimg32", "ntmarta",
    "powrprof", "propsys", "dwmapi", "dxgi", "d3d11", "opengl32", "twain_32",
}


def classify_libraries(libs) -> dict[str, Any]:
    """Map every imported function to at most one capability bucket."""
    hits: dict[str, list[dict[str, str]]] = {}
    unclassified = 0
    total = 0
    runtime = 0
    for lib in libs:
        module = _normalize_module(lib.name)
        table = MODULES.get(module)
        if table is None:
            # API sets forward to real modules; map them back where we can.
            if module.startswith("api-ms-win-core"):
                table = MODULES.get("kernel32")
            elif module in ("kernelbase", "kernel.appcore"):
                table = MODULES.get("kernel32")
            elif module in ("sechost", "sspicli"):
                table = MODULES.get("advapi32")
        for func in lib.functions:
            total += 1
            category = _match(table, func) if table else None
            if category is None and module in MODULE_DEFAULT:
                category = MODULE_DEFAULT[module]
            if category is None and module.startswith("api-ms-win-crt"):
                category = "crt"
            if category is None and module.startswith("python3"):
                category = "python"
            if category is None and (module in RUNTIME_MODULES
                                     or module.startswith("api-ms-win-core")):
                category = "runtime"
                runtime += 1
            if category is None:
                unclassified += 1
                continue
            hits.setdefault(category, []).append({"dll": lib.name, "api": func})
    return {"categories": hits, "total": total, "unclassified": unclassified,
            "runtime": runtime}


# How much of the category list is allowed to count as evidence.
# The old formula (max + sum(rest) // 3) made *breadth itself* the accusation: a
# program that touches 20 innocuous buckets (task manager, a shell, an IDE) scored
# like a keylogger. Capability breadth saturates, so the weight is capped too.
FULL_WEIGHT_CATEGORIES = 6    # the first six categories count in full
DECAY_AFTER = 12              # from here on the remaining back-benches are ignored
DECAY_DIVISOR = 6             # categories 7..11 count for 1/6 of their weight

# Hard ceiling on what the import table alone may contribute. Even after the
# breadth decay above, a large program that legitimately touches ten buckets
# (task manager, shell, debugger, IDE) still accumulated enough to look alarming.
# Imports describe what a binary *can reach for*, never what it does, so they are
# not allowed to decide the verdict on their own: string evidence, packing and a
# broken signature all add on top of this cap.
IMPORT_SCORE_CAP = 45


def category_score(categories: dict[str, list[dict[str, str]]]) -> int:
    """Dominant capabilities, with breadth saturating instead of accumulating."""
    weights = sorted((CATEGORY_INFO.get(name, ("", 0))[1] for name in categories),
                     reverse=True)
    if not weights:
        return 0
    total = 0
    for index, weight in enumerate(weights):
        if index < FULL_WEIGHT_CATEGORIES:
            total += weight
        elif index < DECAY_AFTER:
            total += weight // DECAY_DIVISOR
        else:
            break
    return min(total, IMPORT_SCORE_CAP)
