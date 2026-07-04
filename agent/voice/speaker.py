import threading
import queue

VOICE_TEMPLATES = {
    "camera_access": (
        "Attention. Your camera was just activated by {process}. "
        "{explanation}. Threat level: {level}."
    ),
    "mic_access": (
        "Heads up. Your microphone is now active. "
        "Process responsible: {process}. {explanation}."
    ),
    "usb_insert": (
        "A new USB device was connected. Device: {device}. "
        "{explanation}."
    ),
    "bluetooth": (
        "Bluetooth device {device} just connected. "
        "{explanation}."
    ),
    "screen_capture": (
        "Warning. A process is capturing your screen. "
        "Application: {process}. {explanation}."
    ),
    "keyboard_hook": (
        "Alert. A low-level keyboard hook was detected. "
        "This can indicate a keylogger. Process: {process}. "
        "{explanation}."
    ),
    "unknown_process": (
        "An unrecognized process just started. "
        "Name: {process}. Location: {path}. {explanation}."
    ),
    "network_suspicious": (
        "Unusual network activity detected. "
        "{process} is connecting to {ip} on port {port}. "
        "{explanation}."
    ),
    "idle_anomaly": (
        "While your system was idle, unusual activity occurred. "
        "{explanation}."
    ),
    "ransomware_burst": (
        "Critical alert. Ransomware behavior detected. "
        "{explanation}. Disconnect from network immediately."
    ),
    "all_clear": "System check complete. Everything looks normal.",
}


class JarvisVoice:
    def __init__(self, rate=165, volume=0.95):
        self.rate = rate
        self.volume = volume
        self.muted = False
        self._queue = queue.Queue()
        self._engine = None
        self._init_engine()
        threading.Thread(target=self._worker, daemon=True).start()

    def _init_engine(self):
        try:
            import pyttsx3

            self._engine = pyttsx3.init()
            self._engine.setProperty("rate", self.rate)
            self._engine.setProperty("volume", self.volume)
            voices = self._engine.getProperty("voices")
            for v in voices:
                name = v.name.lower()
                if "david" in name or "mark" in name or "zira" in name:
                    self._engine.setProperty("voice", v.id)
                    break
        except Exception:
            self._engine = None

    def speak(self, template_key: str, **kwargs):
        if self.muted or self._engine is None:
            return
        template = VOICE_TEMPLATES.get(template_key, "")
        if not template:
            return
        try:
            text = template.format(**kwargs)
            self._queue.put(text)
        except KeyError:
            pass

    def speak_raw(self, text: str):
        if not self.muted and self._engine is not None:
            self._queue.put(text)

    def _worker(self):
        while True:
            try:
                text = self._queue.get(timeout=1)
            except queue.Empty:
                continue
            if self._engine is not None:
                try:
                    self._engine.say(text)
                    self._engine.runAndWait()
                except Exception:
                    pass

    def set_muted(self, muted: bool):
        self.muted = muted

    def toggle_mute(self):
        self.muted = not self.muted
        return self.muted
