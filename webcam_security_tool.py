"""
camera_control_final_v2.py
Final Universal Camera Control Tool (merged & fixed detection)

- Robust camera detection via PowerShell (single-string command, searches multiple classes)
- System-wide enable/disable using PowerShell PnP cmdlets
- Password (plain text), change password, logs
- Clean dark Tkinter UI with logo
- Optional OpenCV Test Camera preview (if opencv-python installed)
"""

import os
import sys
import ctypes
import subprocess
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
from PIL import Image, ImageTk
import datetime
import getpass
import shlex
import threading
import time

# optional OpenCV
try:
    import cv2
except Exception:
    cv2 = None

# ---------------- Config ----------------
APP_NAME = "CameraControlFinal"
PASSWORD_FILE = "password.txt"
LOG_FILE = "logs.txt"
DEFAULT_PASSWORD = "crackin123"
LOG_ENCODING = "utf-8"

# ---------------- Helpers ----------------
def resource_path(rel_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, rel_path)

def ensure_password_file():
    if not os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "w", encoding=LOG_ENCODING) as f:
            f.write(DEFAULT_PASSWORD)

def read_password():
    try:
        with open(PASSWORD_FILE, "r", encoding=LOG_ENCODING) as f:
            return f.read().strip()
    except Exception:
        return ""

def write_password(new_pw):
    with open(PASSWORD_FILE, "w", encoding=LOG_ENCODING) as f:
        f.write(new_pw.strip())

def write_log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = getpass.getuser()
    line = f"{ts} | {user} | {msg}\n"
    try:
        with open(LOG_FILE, "a", encoding=LOG_ENCODING) as f:
            f.write(line)
    except Exception:
        pass

# ---------------- Admin helpers ----------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def relaunch_as_admin():
    params = f'"{os.path.abspath(sys.argv[0])}"'
    if len(sys.argv) > 1:
        params += " " + " ".join(shlex.quote(a) for a in sys.argv[1:])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return True
    except Exception:
        return False

# ---------------- PowerShell helpers ----------------
def powershell_run(command_str):
    """Run a single-string PowerShell command and return CompletedProcess or None if Powershell missing."""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command_str],
            capture_output=True, text=True, encoding="utf-8", shell=False
        )
        return proc
    except FileNotFoundError:
        return None

def get_camera_devices():
    """
    Robust camera detection.
    Returns list of (InstanceId, Status) tuples, or (None, error_message) if PowerShell missing.
    Searches multiple classes because some systems expose cameras as Image/Media.
    """
    ps_cmd = (
        "Get-PnpDevice -Class Camera,Image,Media | "
        "Select-Object -Property @{Name='Id';Expression={$_.InstanceId}},@{Name='Status';Expression={$_.Status}} | "
        "ForEach-Object { \"{0}||{1}\" -f $_.Id, $_.Status }"
    )
    proc = powershell_run(ps_cmd)
    if proc is None:
        return None, "PowerShell unavailable."
    out = (proc.stdout or "").strip()
    if proc.returncode != 0 and not out:
        write_log(f"Get camera devices failed: {proc.stderr.strip()}")
        return [], f"Error querying devices: {proc.stderr.strip()}"
    devices = []
    for line in out.splitlines():
        if "||" in line:
            inst, status = line.split("||", 1)
            devices.append((inst.strip(), status.strip()))
    # dedupe preserving order
    seen = set()
    unique = []
    for inst, status in devices:
        if inst not in seen:
            seen.add(inst)
            unique.append((inst, status))
    return unique, None

def disable_device(instance_id):
    cmd = f"Disable-PnpDevice -InstanceId \"{instance_id}\" -Confirm:$false"
    proc = powershell_run(cmd)
    if proc is None:
        return False, "PowerShell unavailable."
    if proc.returncode == 0:
        write_log(f"Disabled device {instance_id}")
        return True, None
    else:
        err = (proc.stderr or proc.stdout or "").strip()
        write_log(f"Failed disable {instance_id}: {err}")
        return False, (err or f"rc={proc.returncode}")

def enable_device(instance_id):
    cmd = f"Enable-PnpDevice -InstanceId \"{instance_id}\" -Confirm:$false"
    proc = powershell_run(cmd)
    if proc is None:
        return False, "PowerShell unavailable."
    if proc.returncode == 0:
        write_log(f"Enabled device {instance_id}")
        return True, None
    else:
        err = (proc.stderr or proc.stdout or "").strip()
        write_log(f"Failed enable {instance_id}: {err}")
        return False, (err or f"rc={proc.returncode}")

# ---------------- Bulk actions ----------------
def disable_all_cameras():
    devices, err = get_camera_devices()
    if devices is None:
        return False, err
    if not devices:
        return False, "No camera devices detected."
    failures = []
    for inst, _ in devices:
        ok, ferr = disable_device(inst)
        if not ok:
            failures.append((inst, ferr))
    if failures:
        return False, f"Some devices failed to disable. See {LOG_FILE}."
    return True, "All detected cameras disabled."

def enable_all_cameras():
    devices, err = get_camera_devices()
    if devices is None:
        return False, err
    if not devices:
        return False, "No camera devices detected."
    failures = []
    for inst, _ in devices:
        ok, ferr = enable_device(inst)
        if not ok:
            failures.append((inst, ferr))
    if failures:
        return False, f"Some devices failed to enable. See {LOG_FILE}."
    return True, "All detected cameras enabled."

def check_camera_status():
    devices, err = get_camera_devices()
    if devices is None:
        return None, err
    if not devices:
        return False, "No cameras detected"
    enabled = any(status.lower() in ("ok", "running") or "ok" in status.lower() for (_id, status) in devices)
    return enabled, f"{len(devices)} camera(s) detected"

# ---------------- OpenCV preview (optional) ----------------
def find_available_camera(max_index=10, timeout=0.4):
    """Scan for an available camera with different backends; returns (index, backend) or (None, None)."""
    if cv2 is None:
        return None, None
    backends = []
    try:
        backends.append(cv2.CAP_DSHOW)
    except Exception:
        pass
    try:
        backends.append(cv2.CAP_MSMF)
    except Exception:
        pass
    backends.append(cv2.CAP_ANY)
    for backend in backends:
        for idx in range(max_index):
            try:
                cap = cv2.VideoCapture(idx, backend)
                time.sleep(timeout)
                if cap.isOpened():
                    cap.release()
                    return idx, backend
                cap.release()
            except Exception:
                continue
    return None, None

class CameraPreviewThread(threading.Thread):
    def __init__(self, index, backend, on_stop=None):
        super().__init__(daemon=True)
        self.index = index
        self.backend = backend
        self.on_stop = on_stop
        self._stop = threading.Event()
    def stop(self):
        self._stop.set()
    def run(self):
        if cv2 is None:
            messagebox.showerror("OpenCV missing", "Install opencv-python for Test Camera preview.")
            if self.on_stop: self.on_stop()
            return
        try:
            cap = cv2.VideoCapture(self.index, self.backend)
            if not cap.isOpened():
                messagebox.showerror("Camera Error", f"Failed to open camera index {self.index}")
                if self.on_stop: self.on_stop()
                return
            write_log(f"Preview started index {self.index}")
            while not self._stop.is_set():
                ret, frame = cap.read()
                if not ret:
                    break
                cv2.imshow("Camera Preview (press q to close)", frame)
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
            cap.release()
            cv2.destroyAllWindows()
        except Exception as e:
            write_log(f"Preview error: {e}")
        finally:
            if self.on_stop: self.on_stop()

# ---------------- UI ----------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Camera Control - Final")
        self.configure(bg="#0f1114")
        self.geometry("620x500")
        self.resizable(False, False)
        self.preview_thread = None
        self._build_ui()
        self._refresh_devices()

    def _build_ui(self):
        top = tk.Frame(self, bg="#0f1114")
        top.pack(pady=10)
        logo_path = resource_path("logo.png")
        if os.path.exists(logo_path):
            try:
                img = Image.open(logo_path).resize((64,64), Image.LANCZOS)
                self.logo_tk = ImageTk.PhotoImage(img)
                tk.Label(top, image=self.logo_tk, bg="#0f1114").grid(row=0, column=0, rowspan=2, padx=12)
            except Exception:
                pass
        tk.Label(top, text="Crackin — Camera Security", fg="#e8eef1", bg="#0f1114", font=("Segoe UI", 16, "bold")).grid(row=0, column=1, sticky="w")
        tk.Label(top, text="System-wide camera control (Windows)", fg="#bfc9cf", bg="#0f1114", font=("Segoe UI", 9)).grid(row=1, column=1, sticky="w")
        top_btns = tk.Frame(top, bg="#0f1114")
        top_btns.grid(row=0, column=2, rowspan=2, padx=8)
        tk.Button(top_btns, text="Change Password", command=self._change_password, bg="#2f3b44", fg="white", bd=0).pack(padx=4, pady=4)
        tk.Button(top_btns, text="View Logs", command=self._view_logs, bg="#2f3b44", fg="white", bd=0).pack(padx=4, pady=4)

        status_frame = tk.Frame(self, bg="#15181c")
        status_frame.pack(padx=20, pady=12, fill="x")
        self.status_var = tk.StringVar(value="Status: Unknown")
        self.status_lbl = tk.Label(status_frame, textvariable=self.status_var, fg="#ffffff", bg="#15181c", font=("Segoe UI", 12, "bold"))
        self.status_lbl.pack(side="left", padx=12, pady=12)
        self.last_action_var = tk.StringVar(value="Last action: None")
        tk.Label(status_frame, textvariable=self.last_action_var, fg="#aab4ba", bg="#15181c").pack(side="right", padx=12)

        list_frame = tk.Frame(self, bg="#0f1114")
        list_frame.pack(padx=20, pady=8, fill="both")
        tk.Label(list_frame, text="Detected Cameras (InstanceId | Status):", fg="#cbd5da", bg="#0f1114").pack(anchor="w")
        self.device_box = tk.Listbox(list_frame, bg="#181a1d", fg="#eef2f3", height=8, width=86, bd=0, highlightthickness=0)
        self.device_box.pack(pady=8)

        btns = tk.Frame(self, bg="#0f1114")
        btns.pack(pady=8)
        tk.Button(btns, text="Disable All Cameras", bg="#c64b49", fg="white", width=20, command=self._on_disable).grid(row=0, column=0, padx=8, pady=6)
        tk.Button(btns, text="Enable All Cameras", bg="#2eb07d", fg="white", width=20, command=self._on_enable).grid(row=0, column=1, padx=8, pady=6)
        tk.Button(btns, text="Test Camera", bg="#3b82f6", fg="white", width=14, command=self._on_test_camera).grid(row=0, column=2, padx=8)
        tk.Button(btns, text="Refresh", bg="#2f3b44", fg="white", width=12, command=self._refresh_devices).grid(row=1, column=0, columnspan=3, pady=8)

        footer = tk.Frame(self, bg="#0f1114")
        footer.pack(side="bottom", fill="x", pady=8)
        tk.Label(footer, text=f"Log: {os.path.abspath(LOG_FILE)}    Password: {os.path.abspath(PASSWORD_FILE)}", fg="#7e8b90", bg="#0f1114").pack()

    def _prompt_pw(self, prompt="Enter password:"):
        return simpledialog.askstring("Password required", prompt, show="*")

    def _require_password(self):
        entered = self._prompt_pw("Enter your password to continue:")
        if entered is None:
            return False
        if entered == read_password():
            return True
        messagebox.showerror("Authentication failed", "Incorrect password.")
        write_log("Incorrect password attempt")
        return False

    def _refresh_devices(self):
        self.device_box.delete(0, tk.END)
        devices, err = get_camera_devices()
        if devices is None:
            self.device_box.insert(tk.END, "PowerShell not available on this system.")
            self.status_var.set("Status: PowerShell missing")
            self.status_lbl.config(fg="#ffd166")
            return
        if not devices:
            self.device_box.insert(tk.END, "No cameras detected.")
            self.status_var.set("Status: No cameras")
            self.status_lbl.config(fg="#ffd166")
            return
        for inst, status in devices:
            self.device_box.insert(tk.END, f"{inst}  |  {status}")
        enabled_any, txt = check_camera_status()
        if enabled_any is None:
            self.status_var.set(f"Status: {txt}")
            self.status_lbl.config(fg="#ffd166")
        elif enabled_any:
            self.status_var.set(f"Status: Enabled — {txt}")
            self.status_lbl.config(fg="#2eb07d")
        else:
            self.status_var.set(f"Status: Disabled — {txt}")
            self.status_lbl.config(fg="#c64b49")

    def _on_disable(self):
        if not self._require_password():
            return
        if not messagebox.askyesno("Confirm", "Disable all detected cameras? This will block camera system-wide."):
            return
        ok, msg = disable_all_cameras()
        if ok:
            messagebox.showinfo("Success", msg)
            self.last_action_var.set("Last action: Disabled all cameras")
            write_log("Disabled all cameras (user)")
            self.status_lbl.config(fg="#c64b49")
        else:
            messagebox.showwarning("Partial/Failed", msg)
            self.last_action_var.set("Last action: Disable attempted")
            write_log("Disable attempted - partial/failure")
            self.status_lbl.config(fg="#c64b49")
        self._refresh_devices()

    def _on_enable(self):
        if not self._require_password():
            return
        if not messagebox.askyesno("Confirm", "Enable all detected cameras?"):
            return
        ok, msg = enable_all_cameras()
        if ok:
            messagebox.showinfo("Success", msg)
            self.last_action_var.set("Last action: Enabled all cameras")
            write_log("Enabled all cameras (user)")
            self.status_lbl.config(fg="#2eb07d")
        else:
            messagebox.showwarning("Partial/Failed", msg)
            self.last_action_var.set("Last action: Enable attempted")
            write_log("Enable attempted - partial/failure")
            self.status_lbl.config(fg="#2eb07d")
        self._refresh_devices()

    def _on_test_camera(self):
        if cv2 is None:
            messagebox.showerror("OpenCV missing", "Install opencv-python to use Test Camera preview.")
            return
        idx, backend = find_available_camera()
        if idx is None:
            messagebox.showerror("No Camera", "No available camera found by OpenCV.")
            write_log("Test Camera failed - no camera found")
            return
        self._toggle_buttons(state=True)
        write_log(f"Starting preview (index {idx}, backend {backend})")
        def on_stop():
            self._toggle_buttons(state=False)
            write_log("Preview stopped")
        self.preview_thread = CameraPreviewThread(idx, backend, on_stop=on_stop)
        self.preview_thread.start()

    def _toggle_buttons(self, state):
        for w in (self.btn_disable, self.btn_enable):
            try:
                w.config(state="disabled" if state else "normal")
            except Exception:
                pass

    def _change_password(self):
        current = simpledialog.askstring("Verify", "Enter current password:", show="*")
        if current is None:
            return
        if current != read_password():
            messagebox.showerror("Error", "Incorrect current password.")
            return
        newpw = simpledialog.askstring("New Password", "Enter new password:", show="*")
        if newpw is None or newpw.strip() == "":
            messagebox.showwarning("Cancelled", "Password not changed.")
            return
        confirm = simpledialog.askstring("Confirm", "Re-enter new password:", show="*")
        if confirm is None or confirm != newpw:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        write_password(newpw)
        messagebox.showinfo("Success", "Password changed.")
        write_log("Password changed by user")

    def _view_logs(self):
        if not os.path.exists(LOG_FILE):
            messagebox.showinfo("Logs", "No logs yet.")
            return
        try:
            with open(LOG_FILE, "r", encoding=LOG_ENCODING) as f:
                content = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Open log failed: {e}")
            return
        win = tk.Toplevel(self)
        win.title("Logs")
        win.geometry("900x500")
        txt = tk.Text(win, wrap="none")
        txt.insert("1.0", content)
        txt.configure(state="disabled")
        txt.pack(fill="both", expand=True)
        def save_as():
            p = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text","*.txt")])
            if p:
                try:
                    with open(p, "w", encoding=LOG_ENCODING) as out:
                        out.write(content)
                    messagebox.showinfo("Saved", f"Logs saved to: {p}")
                except Exception as e:
                    messagebox.showerror("Error", f"Save failed: {e}")
        tk.Button(win, text="Save As...", command=save_as).pack(pady=6)

# ---------------- Startup ----------------
def main():
    ensure_password_file()
    if not is_admin():
        root = tk.Tk()
        root.withdraw()
        ask = messagebox.askyesno("Administrator required",
                                  "This tool must run with Administrator rights to enable/disable cameras.\nRelaunch as administrator now?")
        root.destroy()
        if ask:
            relaunch_as_admin()
            sys.exit(0)
        else:
            messagebox.showinfo("Info", "Running without admin - device changes will fail.")
    app = App()
    app.mainloop()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_log(f"Unhandled exception: {e}")
        raise
