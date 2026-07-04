import psutil
import os
import subprocess
from pathlib import Path
from agent.watchers.base_watcher import BaseWatcher


def _check_signature(exe_path: str) -> bool:
    if not exe_path or not os.path.exists(exe_path):
        return False
    try:
        import ctypes
        from ctypes import wintypes

        win_trust = ctypes.WinDLL("wintrust.dll")
        soft_pub = ctypes.WinDLL("crypt32.dll")

        WINTRUST_ACTION_ID = ctypes.c_byte * 16
        WVTPolicyGUID = WINTRUST_ACTION_ID(
            0x01, 0x05, 0x0A, 0x61,
            0xC7, 0x86, 0x0B, 0x4E,
            0x96, 0xE7, 0xF8, 0x1A,
            0x02, 0x03, 0x00, 0x00,
        )

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", ctypes.c_wchar_p),
                ("hFile", ctypes.c_void_p),
                ("pgKnownSubject", ctypes.c_void_p),
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("pFile", ctypes.c_void_p),
                ("pgKnownSubject", ctypes.c_void_p),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", ctypes.c_void_p),
                ("pwszURLReference", ctypes.c_wchar_p),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
                ("pActionData", ctypes.c_void_p),
                ("dwReturnChoice", wintypes.DWORD),
            ]

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(file_info)
        file_info.pwszFilePath = exe_path

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(trust_data)
        trust_data.dwUnionChoice = 1
        trust_data.pFile = ctypes.pointer(file_info)
        trust_data.dwStateAction = 2

        result = win_trust.WinVerifyTrust(
            0, ctypes.byref(WVTPolicyGUID), ctypes.byref(trust_data)
        )
        trust_data.dwStateAction = 3
        win_trust.WinVerifyTrust(0, ctypes.byref(WVTPolicyGUID), ctypes.byref(trust_data))

        return result == 0
    except Exception:
        return False


def _has_visible_window(pid: int) -> bool:
    try:
        import ctypes
        user32 = ctypes.WinDLL("user32")

        EnumWindows = user32.EnumWindows
        GetWindowThreadProcessId = user32.GetWindowThreadProcessId
        IsWindowVisible = user32.IsWindowVisible

        result = [False]

        def callback(hwnd, lparam):
            pid_buf = wintypes.DWORD()
            GetWindowThreadProcessId(hwnd, ctypes.byref(pid_buf))
            if pid_buf.value == pid and IsWindowVisible(hwnd):
                result[0] = True
                return False
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        EnumWindows(WNDENUMPROC(callback), 0)
        return result[0]
    except Exception:
        return False


SUSPICIOUS_PARENT_PAIRS = {
    "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
    "powerpnt.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
    "outlook.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
    "chrome.exe": ["cmd.exe", "powershell.exe"],
    "firefox.exe": ["cmd.exe", "powershell.exe"],
    "explorer.exe": ["powershell.exe", "cmd.exe"],
}


class ProcessWatcher(BaseWatcher):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.known_pids = set()
        self._signature_cache = {}
        self._suspicious_procs = []

    def poll(self) -> dict:
        features = {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "is_signed": 1.0,
            "from_temp": 0.0,
            "parent_child_pair": 0.0,
            "has_window": 1.0,
            "encoded_cmdline": 0.0,
        }

        new_procs = []
        for proc in psutil.process_iter(
            ["pid", "name", "exe", "ppid", "cpu_percent", "memory_percent"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                if pid in self.known_pids:
                    continue
                self.known_pids.add(pid)
                new_procs.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not new_procs:
            return features

        self._suspicious_procs = []
        signed_count = 0
        temp_count = 0
        suspicious_count = 0
        window_count = 0

        for info in new_procs:
            exe = info.get("exe") or ""
            name = (info.get("name") or "").lower()

            if exe in self._signature_cache:
                is_signed = self._signature_cache[exe]
            else:
                is_signed = _check_signature(exe)
                self._signature_cache[exe] = is_signed

            from_temp = any(
                p in exe.lower()
                for p in ["\\temp\\", "\\appdata\\local\\temp\\", "\\tmp\\", "\\appdata\\local\\microsoft\\windows\\inetcache\\"]
            )

            parent_child = False
            parent_name = ""
            try:
                parent = psutil.Process(info.get("ppid", 0))
                parent_name = parent.name().lower()
                child_name = name
                if parent_name in SUSPICIOUS_PARENT_PAIRS:
                    if child_name in SUSPICIOUS_PARENT_PAIRS[parent_name]:
                        parent_child = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            encoded = any(
                enc in name
                for enc in ["base64", "encoded", "invoke-expression", "iex", "bypass"]
            )

            if is_signed:
                signed_count += 1
            if from_temp:
                temp_count += 1
            if parent_child:
                suspicious_count += 1
            if _has_visible_window(info["pid"]):
                window_count += 1

            if (not is_signed and from_temp) or parent_child or encoded:
                self._suspicious_procs.append({
                    "pid": info["pid"],
                    "name": name,
                    "exe": exe,
                    "parent_name": parent_name,
                    "is_unsigned": not is_signed,
                    "from_temp": from_temp,
                    "parent_child_pair": parent_child,
                    "has_window": _has_visible_window(info["pid"]),
                    "encoded_cmdline": encoded,
                    "cpu_percent": info.get("cpu_percent", 0) or 0,
                    "memory_percent": info.get("memory_percent", 0) or 0,
                })

        total = len(new_procs)
        features["cpu_percent"] = sum(
            p.get("cpu_percent", 0) or 0 for p in new_procs
        ) / total
        features["memory_percent"] = sum(
            p.get("memory_percent", 0) or 0 for p in new_procs
        ) / total
        features["is_signed"] = signed_count / total
        features["from_temp"] = temp_count / total
        features["parent_child_pair"] = suspicious_count / total
        features["has_window"] = window_count / total
        features["encoded_cmdline"] = 1.0 if self._suspicious_procs else 0.0

        return features

    def build_events(self, features: dict, anomaly_result: dict) -> list:
        events = []
        for proc in self._suspicious_procs:
            severity = "MEDIUM"
            if proc["parent_child_pair"]:
                severity = "CRITICAL"
            elif proc["is_unsigned"] and proc["from_temp"]:
                severity = "HIGH"
            elif proc["encoded_cmdline"]:
                severity = "HIGH"

            events.append(
                self.emit(
                    {
                        "type": "UNKNOWN_PROCESS",
                        "process_name": proc["name"],
                        "pid": proc["pid"],
                        "exe_path": proc["exe"],
                        "severity": severity,
                        "is_unsigned": proc["is_unsigned"],
                        "from_temp": proc["from_temp"],
                        "parent_child_pair": proc["parent_child_pair"],
                        "has_window": proc["has_window"],
                        "encoded_cmdline": proc["encoded_cmdline"],
                        "parent_name": proc.get("parent_name", ""),
                        "cpu_percent": proc["cpu_percent"],
                        "memory_percent": proc["memory_percent"],
                    }
                )
            )
        return events
