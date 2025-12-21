import hashlib
import sys
import os
import winreg
import ctypes
from pathlib import Path
import tkinter as tk
from tkinter import messagebox
import json
import subprocess
import time
import secrets
import string


class KeyGuardRestrictor:
    def __init__(self):
        self.system_dir = Path(os.getenv('ProgramData')) / 'KeyGuardRestrictor'
        self.config_file = self.system_dir / '.keyguard_config'
        self.lock_file = Path(os.getenv('TEMP')) / 'keyguard.lock'
        self.active_lock = Path(os.getenv('TEMP')) / 'keyguard_active.lock'

        try:
            self.system_dir.mkdir(parents=True, exist_ok=True)
            ctypes.windll.kernel32.SetFileAttributesW(str(self.system_dir), 0x02)  # Hidden
        except Exception as e:
            print(f"Warning: Could not create system directory: {e}")

    def hash_passphrase(self, passphrase):
        salt = b'KeyGuard_Salt_2025'
        salted = salt + passphrase.encode('utf-8')
        return hashlib.sha256(salted).hexdigest()

    def generate_recovery_code(self):
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(20))

    def save_hash_to_disk(self, hashed_pass, recovery_hash=None):
        config = {
            'hash': hashed_pass,
            'version': '1.1',  # Updated for recovery support
            'algorithm': 'SHA-256',
            'created': time.strftime('%Y-%m-%d %H:%M:%S'),
            'recovery_enabled': recovery_hash is not None,
        }
        if recovery_hash:
            config['recovery_hash'] = recovery_hash

        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            ctypes.windll.kernel32.SetFileAttributesW(str(self.config_file), 0x01 | 0x02)
            self.save_hash_to_registry(hashed_pass, recovery_hash)
            return True
        except Exception as e:
            print(f"Error saving to disk: {e}")
            return False

    def save_hash_to_registry(self, hashed_pass, recovery_hash=None):
        try:
            key_path = r'SOFTWARE\KeyGuardRestrictor'
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(key, 'SecureHash', 0, winreg.REG_SZ, hashed_pass)
            if recovery_hash:
                winreg.SetValueEx(key, 'RecoveryHash', 0, winreg.REG_SZ, recovery_hash)
            else:
                try:
                    winreg.DeleteValue(key, 'RecoveryHash')
                except:
                    pass
            winreg.CloseKey(key)
            return True
        except Exception as e:
            print(f"Registry write failed: {e}")
            return False

    def load_hashes(self):
        if not self.config_file.exists():
            return None, None
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                return config.get('hash'), config.get('recovery_hash')
        except:
            return self.load_from_registry_fallback()

    def load_from_registry_fallback(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'SOFTWARE\KeyGuardRestrictor', 0, winreg.KEY_READ)
            main_hash, _ = winreg.QueryValueEx(key, 'SecureHash')
            recovery_hash = None
            try:
                recovery_hash, _ = winreg.QueryValueEx(key, 'RecoveryHash')
            except:
                pass
            winreg.CloseKey(key)
            return main_hash, recovery_hash
        except:
            return None, None

    def verify_passphrase_or_recovery(self, entry):
        main_hash, recovery_hash = self.load_hashes()
        if main_hash is None:
            return False, False
        entered_hash = self.hash_passphrase(entry)
        return (entered_hash == main_hash), (recovery_hash and entered_hash == recovery_hash)

    def disable_recovery(self):
        main_hash, _ = self.load_hashes()
        if main_hash:
            self.save_hash_to_disk(main_hash, recovery_hash=None)

    def instant_lock_system(self):
        self.active_lock.write_text('ACTIVE_LOCK')
        self.lock_file.write_text('LOCKED')
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  r'Software\Microsoft\Windows\CurrentVersion\Policies\System')
            winreg.SetValueEx(key, 'DisableTaskMgr', 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, 'DisableRegistryTools', 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except:
            pass
        try:
            subprocess.run(['taskkill', '/F', '/IM', 'explorer.exe'], capture_output=True, timeout=2)
        except:
            pass

    def unlock_system(self):
        if self.lock_file.exists():
            self.lock_file.unlink()
        if self.active_lock.exists():
            self.active_lock.unlink()
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                               r'Software\Microsoft\Windows\CurrentVersion\Policies\System',
                               0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, 'DisableTaskMgr', 0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(key, 'DisableRegistryTools', 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
        except:
            pass
        try:
            subprocess.Popen(['explorer.exe'])
        except:
            pass

    def add_to_startup_instant(self):
        script_path = os.path.abspath(__file__)
        python_dir = Path(sys.executable).parent
        pythonw_exe = python_dir / 'pythonw.exe'
        python_exe = str(pythonw_exe) if pythonw_exe.exists() else sys.executable
        startup_cmd = f'"{python_exe}" "{script_path}" --instant-lock'

        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                               r'Software\Microsoft\Windows\CurrentVersion\Run',
                               0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, 'KeyGuardRestrictor', 0, winreg.REG_SZ, startup_cmd)
            winreg.CloseKey(key)
            self.create_startup_shortcut(startup_cmd)
            return True
        except:
            return False

    def create_startup_shortcut(self, command):
        try:
            startup_folder = Path(os.getenv('APPDATA')) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'
            vbs_path = startup_folder / 'KeyGuardRestrictor.vbs'
            vbs_content = f'''Set WshShell = CreateObject("WScript.Shell")
WshShell.Run """{sys.executable}"" ""{os.path.abspath(__file__)}"" --instant-lock", 0, False'''
            with open(vbs_path, 'w') as f:
                f.write(vbs_content)
        except:
            pass

    def remove_from_startup(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                               r'Software\Microsoft\Windows\CurrentVersion\Run',
                               0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, 'KeyGuardRestrictor')
            winreg.CloseKey(key)
        except:
            pass
        try:
            vbs_path = Path(os.getenv('APPDATA')) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup' / 'KeyGuardRestrictor.vbs'
            if vbs_path.exists():
                vbs_path.unlink()
        except:
            pass

    def delete_configuration(self):
        try:
            if self.config_file.exists():
                ctypes.windll.kernel32.SetFileAttributesW(str(self.config_file), 0x80)
                self.config_file.unlink()
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r'SOFTWARE\KeyGuardRestrictor')
        except:
            pass


class InstantLockGUI:
    def __init__(self, guard):
        self.guard = guard
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title("KeyGuard - Authentication Required")
        self.root.attributes('-topmost', True)
        self.root.attributes('-fullscreen', True)
        self.root.configure(bg='#1a1a1a')
        self.root.overrideredirect(True)
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)
        self.root.bind('<Alt-F4>', lambda e: 'break')

        self.attempts = 0
        self.max_attempts = 5
        self.create_widgets()
        self.root.update_idletasks()

    def create_widgets(self):
        container = tk.Frame(self.root, bg='#1a1a1a')
        container.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        tk.Label(container, text="🔒", font=("Arial", 72), bg='#1a1a1a', fg='#ffffff').pack(pady=20)
        tk.Label(container, text="System Locked", font=("Arial", 28, "bold"), bg='#1a1a1a', fg='#ffffff').pack(pady=10)
        tk.Label(container, text="KeyGuard Instant Boot Protection\nEnter passphrase to unlock", font=("Arial", 12),
                 bg='#1a1a1a', fg='#cccccc').pack(pady=10)
        tk.Label(container, text="💡 Forgotten? Try your one-time recovery code", font=("Arial", 9, "italic"),
                 bg='#1a1a1a', fg='#3498db').pack(pady=5)

        entry_frame = tk.Frame(container, bg='#1a1a1a')
        entry_frame.pack(pady=30)
        self.pass_entry = tk.Entry(entry_frame, show="●", width=30, font=("Arial", 14), bg='#2d2d2d',
                                   fg='#ffffff', insertbackground='#ffffff', relief=tk.FLAT, bd=10)
        self.pass_entry.pack()
        self.pass_entry.bind('<Return>', lambda e: self.verify())

        tk.Button(container, text="🔓 Unlock System", command=self.verify, font=("Arial", 12, "bold"), width=20,
                  bg='#27ae60', fg='white', relief=tk.FLAT, pady=12).pack(pady=20)

        self.status_label = tk.Label(container, text="", font=("Arial", 10), bg='#1a1a1a', fg='#e74c3c')
        self.status_label.pack(pady=10)
        self.attempts_label = tk.Label(container, text=f"Attempts remaining: {self.max_attempts}",
                                       font=("Arial", 9), bg='#1a1a1a', fg='#7f8c8d')
        self.attempts_label.pack(pady=5)

    def show_and_lock(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.pass_entry.focus_set()
        self.root.mainloop()

    def verify(self):
        entry = self.pass_entry.get()
        if not entry:
            return
        is_main, is_recovery = self.guard.verify_passphrase_or_recovery(entry)

        if is_main or is_recovery:
            if is_recovery:
                self.guard.disable_recovery()
                self.status_label.config(text="✓ Recovery Code Accepted (now disabled)", fg='#f39c12')
            else:
                self.status_label.config(text="✓ Access Granted", fg='#27ae60')
            self.root.after(800, self.unlock_and_close)
        else:
            self.attempts += 1
            remaining = self.max_attempts - self.attempts
            if remaining > 0:
                self.status_label.config(text="✗ Incorrect", fg='#e74c3c')
                self.attempts_label.config(text=f"Attempts remaining: {remaining}", fg='#e74c3c')
                self.pass_entry.delete(0, tk.END)
                self.pass_entry.focus_set()
                self.shake_window()
            else:
                self.status_label.config(text="✗ SYSTEM LOCKED", fg='#c0392b')
                self.attempts_label.config(text="Max attempts exceeded", fg='#c0392b')
                self.pass_entry.config(state='disabled')
                messagebox.showerror("Locked Out", "Maximum attempts reached.\nRestart required.")

    def shake_window(self):
        x = self.root.winfo_x()
        for offset in [10, -10, 10, -10]:
            self.root.geometry(f"+{x + offset}+{self.root.winfo_y()}")
            self.root.update()
            time.sleep(0.05)
        self.root.geometry(f"+{x}+{self.root.winfo_y()}")

    def unlock_and_close(self):
        self.guard.unlock_system()
        self.root.destroy()


class SetupGUI:
    def __init__(self, guard):
        self.guard = guard
        self.root = tk.Tk()
        self.root.title("KeyGuard - Instant Boot Lock Setup")
        self.root.geometry("620x680")
        self.root.resizable(False, False)
        self.root.configure(bg='#ecf0f1')
        x = (self.root.winfo_screenwidth() // 2) - (310)
        y = (self.root.winfo_screenheight() // 2) - (340)
        self.root.geometry(f"620x680+{x}+{y}")
        self.create_widgets()

    def create_widgets(self):
        header = tk.Frame(self.root, bg='#e74c3c', height=100)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="⚡ KeyGuard Instant Boot Lock", font=("Arial", 20, "bold"), bg='#e74c3c', fg='white').pack(pady=20)

        content = tk.Frame(self.root, bg='#ecf0f1')
        content.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)

        warning = tk.Label(content,
                          text="⚠️ This locks your PC instantly on boot • No desktop until correct entry\n"
                               "• Forgetting BOTH passphrase and recovery code = reinstall required",
                          justify=tk.LEFT, bg='#fff3cd', fg='#856404', font=("Arial", 10, "bold"), padx=15, pady=15)
        warning.pack(fill=tk.X, pady=10)

        tk.Label(content, text="Set your main passphrase (8+ characters):", bg='#ecf0f1', font=("Arial", 10, "bold")).pack(anchor='w', pady=(20,5))
        self.pass_entry = tk.Entry(content, show="●", width=40, font=("Arial", 11))
        self.pass_entry.pack(pady=5)
        self.confirm_entry = tk.Entry(content, show="●", width=40, font=("Arial", 11))
        self.confirm_entry.pack(pady=5)

        self.show_var = tk.BooleanVar()
        tk.Checkbutton(content, text="Show passphrase", variable=self.show_var, command=self.toggle_show, bg='#ecf0f1').pack(pady=5)

        btn_frame = tk.Frame(content, bg='#ecf0f1')
        btn_frame.pack(pady=40)
        tk.Button(btn_frame, text="⚡ ACTIVATE WITH RECOVERY CODE", command=self.setup,
                  font=("Arial", 12, "bold"), bg='#e74c3c', fg='white', width=30, pady=10).pack()

    def toggle_show(self):
        show = "" if self.show_var.get() else "●"
        self.pass_entry.config(show=show)
        self.confirm_entry.config(show=show)

    def setup(self):
        passphrase = self.pass_entry.get()
        confirm = self.confirm_entry.get()
        if not passphrase or passphrase != confirm:
            messagebox.showerror("Error", "Passphrases empty or do not match")
            return
        if len(passphrase) < 8:
            messagebox.showerror("Error", "Minimum 8 characters")
            return

        recovery_code = self.guard.generate_recovery_code()
        recovery_hash = self.guard.hash_passphrase(recovery_code)

        msg = (f"⚠️ FINAL CONFIRMATION ⚠️\n\n"
               f"Main Passphrase:\n{passphrase}\n\n"
               f"One-Time Recovery Code:\n{recovery_code}\n\n"
               "• Recovery code works only ONCE\n"
               "• It will be permanently disabled after use\n"
               "• Store both securely and separately!\n\n"
               "Activate instant boot lock now?")

        if not messagebox.askyesno("Activate KeyGuard", msg, icon='warning'):
            return

        if self.guard.save_hash_to_disk(self.guard.hash_passphrase(passphrase), recovery_hash):
            self.guard.add_to_startup_instant()
            success_msg = (f"✓ KeyGuard Activated Successfully!\n\n"
                           f"Main Passphrase:\n{passphrase}\n\n"
                           f"Recovery Code (one-time):\n{recovery_code}\n\n"
                           "⚠️ Save both offline now!\n"
                           "⚡ Locks instantly on next boot")
            messagebox.showinfo("Activated", success_msg)
            self.root.quit()


def main():
    guard = KeyGuardRestrictor()

    if len(sys.argv) > 1:
        if sys.argv[1] == '--instant-lock':
            if guard.load_hashes()[0]:
                guard.instant_lock_system()
                InstantLockGUI(guard).show_and_lock()
            else:
                messagebox.showwarning("Not Configured", "Run setup first.")
        elif sys.argv[1] == '--setup':
            SetupGUI(guard).root.mainloop()
        elif sys.argv[1] == '--reset':
            if messagebox.askyesno("Reset", "Remove KeyGuard completely?"):
                guard.delete_configuration()
                guard.remove_from_startup()
                guard.unlock_system()
                messagebox.showinfo("Reset", "KeyGuard removed.")
    else:
        if not guard.load_hashes()[0]:
            messagebox.showinfo("Welcome", "Set up KeyGuard instant boot protection now.")
            SetupGUI(guard).root.mainloop()
        else:
            choice = messagebox.askyesnocancel("KeyGuard Active",
                                              "KeyGuard is active.\n\nYes: Change passphrase\nNo: Disable\nCancel: Exit")
            if choice is True:
                SetupGUI(guard).root.mainloop()
            elif choice is False:
                if messagebox.askyesno("Disable", "Remove boot lock?"):
                    guard.delete_configuration()
                    guard.remove_from_startup()
                    guard.unlock_system()
                    messagebox.showinfo("Disabled", "KeyGuard removed.")


if __name__ == '__main__':
    main()