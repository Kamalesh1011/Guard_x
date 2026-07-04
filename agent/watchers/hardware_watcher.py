import winreg
import psutil
import subprocess
from agent.watchers.base_watcher import BaseWatcher


CAMERA_REGISTRY = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion"
    r"\CapabilityAccessManager\ConsentStore\webcam"
)
MIC_REGISTRY = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion"
    r"\CapabilityAccessManager\ConsentStore\microphone"
)

CAMERA_PROCESS_NAMES = {
    'zoom.exe', 'teams.exe', 'skype.exe', 'discord.exe', 'obs.exe',
    'obs64.exe', 'webex.exe', 'meet.exe', 'camera.exe', 'webcam.exe',
    'youcam.exe', 'xsplit.exe', 'manyCam.exe', 'bandicam.exe',
    'chrome.exe', 'firefox.exe', 'msedge.exe', 'opera.exe',
}

CAMERA_KEYWORDS = ['camera', 'webcam', 'video', 'zoom', 'teams', 'skype', 'discord', 'obs']
MIC_KEYWORDS = ['microphone', 'mic', 'audio', 'recording', 'voice', 'zoom', 'teams', 'skype', 'discord']


class HardwareWatcher(BaseWatcher):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._camera_was_active = False
        self._mic_was_active = False
        self._last_camera_apps = set()
        self._last_mic_apps = set()
        self._camera_just_activated = False
        self._mic_just_activated = False

    def _poll_consent_store(self, registry_path: str) -> set:
        active = set()
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    try:
                        last_used, _ = winreg.QueryValueEx(subkey, "LastUsedTimeStop")
                        if last_used == 0:
                            active.add(subkey_name)
                    except FileNotFoundError:
                        pass
                    winreg.CloseKey(subkey)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass
        return active

    def _detect_camera_by_process(self) -> set:
        active = set()
        try:
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    exe = (proc.info["exe"] or "").lower()
                    if name in CAMERA_PROCESS_NAMES:
                        active.add(proc.info["name"])
                        continue
                    for keyword in CAMERA_KEYWORDS:
                        if keyword in name or keyword in exe:
                            active.add(proc.info["name"])
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        return active

    def _detect_camera_by_device(self) -> set:
        active = set()
        try:
            result = subprocess.run(
                ['powershell', '-Command',
                 'Get-CimInstance Win32_PnPEntity | Where-Object { $_.Name -match "camera|webcam|video" } | Select-Object Name, Status'],
                capture_output=True, text=True, timeout=5,
                creationflags=0x08000000
            )
            for line in result.stdout.split('\n'):
                if 'OK' in line or 'Running' in line:
                    parts = line.strip().split('  ')
                    if parts:
                        active.add(parts[0].strip())
        except Exception:
            pass
        return active

    def _detect_mic_by_process(self) -> set:
        active = set()
        try:
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    exe = (proc.info["exe"] or "").lower()
                    for keyword in MIC_KEYWORDS:
                        if keyword in name or keyword in exe:
                            active.add(proc.info["name"])
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        return active

    def _find_pid_for_app(self, app_name: str):
        name_lower = app_name.lower()
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pname = (proc.info["name"] or "").lower()
                if name_lower in pname or pname in name_lower:
                    return proc.info["pid"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None

    def _get_camera_active(self) -> set:
        registry = self._poll_consent_store(CAMERA_REGISTRY)
        process = self._detect_camera_by_process()
        device = self._detect_camera_by_device()
        return registry | process | device

    def _get_mic_active(self) -> set:
        registry = self._poll_consent_store(MIC_REGISTRY)
        process = self._detect_mic_by_process()
        return registry | process

    def poll(self) -> dict:
        features = {
            "is_first_time": 0.0,
            "is_background": 0.0,
            "is_signed": 1.0,
            "app_is_known": 1.0,
        }

        camera_active = self._get_camera_active()
        mic_active = self._get_mic_active()

        camera_is_on = len(camera_active) > 0
        mic_is_on = len(mic_active) > 0

        new_apps_camera = camera_active - self._last_camera_apps
        new_apps_mic = mic_active - self._last_mic_apps

        self._camera_just_activated = camera_is_on and not self._camera_was_active
        self._mic_just_activated = mic_is_on and not self._mic_was_active

        self._last_camera_apps = camera_active
        self._last_mic_apps = mic_active

        if self._camera_just_activated or new_apps_camera:
            features["is_first_time"] = 1.0
            features["app_is_known"] = 0.0

        if self._mic_just_activated or new_apps_mic:
            features["is_first_time"] = 1.0
            features["app_is_known"] = 0.0

        self._camera_was_active = camera_is_on
        self._mic_was_active = mic_is_on

        return features

    def build_events(self, features: dict, anomaly_result: dict) -> list:
        events = []

        camera_active = self._last_camera_apps
        mic_active = self._last_mic_apps

        camera_turned_on = self._camera_just_activated
        mic_turned_on = self._mic_just_activated

        if camera_turned_on:
            for app in camera_active:
                pid = self._find_pid_for_app(app)
                proc_name = app
                if pid:
                    try:
                        resolved = psutil.Process(pid).name()
                        if resolved:
                            proc_name = resolved
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                events.append(
                    self.emit({
                        "type": "CAMERA_ACCESS",
                        "process_name": proc_name,
                        "pid": pid,
                        "app_package": app,
                        "severity": "HIGH",
                        "is_first_time": True,
                        "is_background": False,
                        "is_signed": True,
                        "app_is_known": False,
                    })
                )

        if mic_turned_on:
            for app in mic_active:
                pid = self._find_pid_for_app(app)
                proc_name = app
                if pid:
                    try:
                        resolved = psutil.Process(pid).name()
                        if resolved:
                            proc_name = resolved
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                events.append(
                    self.emit({
                        "type": "MIC_ACCESS",
                        "process_name": proc_name,
                        "pid": pid,
                        "app_package": app,
                        "severity": "MEDIUM",
                        "is_first_time": True,
                        "is_background": False,
                        "is_signed": True,
                        "app_is_known": False,
                    })
                )

        return events

    def get_hardware_status(self) -> dict:
        camera_active = self._get_camera_active()
        mic_active = self._get_mic_active()

        return {
            "camera": {
                "active": len(camera_active) > 0,
                "apps": list(camera_active),
            },
            "microphone": {
                "active": len(mic_active) > 0,
                "apps": list(mic_active),
            },
        }
