"""
KeyGuard Safe Test Mode
========================
Test the KeyGuard system WITHOUT activating boot-time locking.
This allows you to verify the passphrase system works before full deployment.

SAFE FEATURES:
- Tests authentication UI
- Verifies passphrase storage/retrieval
- NO boot-time activation
- Easy to exit (ESC key or Cancel button)
- No system modifications

Run this first to ensure everything works!
"""

import hashlib
import sys
import os
import json
import tkinter as tk
from tkinter import messagebox
from pathlib import Path
import ctypes

class KeyGuardTestMode:
    def __init__(self):
        # Use test directory instead of system directory
        self.test_dir = Path.home() / '.keyguard_test'
        self.config_file = self.test_dir / 'test_config.json'
        
        # Create test directory
        self.test_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"✓ Test directory: {self.test_dir}")
    
    def hash_passphrase(self, passphrase):
        """Generate SHA-256 hash of passphrase with salt"""
        salt = b'KeyGuard_Salt_2025'
        salted = salt + passphrase.encode('utf-8')
        return hashlib.sha256(salted).hexdigest()
    
    def save_test_hash(self, hashed_pass):
        """Save hash to test directory"""
        config = {
            'hash': hashed_pass,
            'version': '1.0',
            'algorithm': 'SHA-256',
            'test_mode': True
        }
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving test config: {e}")
            return False
    
    def load_test_hash(self):
        """Load stored test hash"""
        if not self.config_file.exists():
            return None
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                return config.get('hash')
        except Exception as e:
            print(f"Error reading test config: {e}")
            return None
    
    def verify_passphrase(self, passphrase):
        """Verify passphrase against stored hash"""
        stored_hash = self.load_test_hash()
        if stored_hash is None:
            return False
        return self.hash_passphrase(passphrase) == stored_hash
    
    def is_configured(self):
        """Check if test passphrase is configured"""
        return self.load_test_hash() is not None
    
    def delete_test_config(self):
        """Remove test configuration"""
        try:
            if self.config_file.exists():
                self.config_file.unlink()
            return True
        except Exception as e:
            print(f"Error deleting test config: {e}")
            return False


class TestSetupGUI:
    def __init__(self, guard):
        self.guard = guard
        self.root = tk.Tk()
        self.root.title("KeyGuard Test Mode")
        
        # Fixed size window - not resizable
        self.root.geometry("550x600")
        self.root.resizable(False, False)
        self.root.configure(bg='#e8f5e9')
        
        # Center window on screen
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (275)
        y = (self.root.winfo_screenheight() // 2) - (300)
        self.root.geometry(f"550x600+{x}+{y}")
        
        # Allow ESC to close
        self.root.bind('<Escape>', lambda e: self.root.quit())
        
        self.create_widgets()
    
    def create_widgets(self):
        # Header section
        header = tk.Frame(self.root, bg='#4caf50', height=80)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        title = tk.Label(header, text="🧪 KeyGuard Test", 
                        font=("Arial", 20, "bold"),
                        bg='#4caf50', fg='white')
        title.pack(pady=25)
        
        # Create scrollable canvas for main content
        canvas = tk.Canvas(self.root, bg='#e8f5e9', highlightthickness=0)
        scrollbar = tk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#e8f5e9')
        
        # Configure scrolling
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack scrollbar and canvas
        canvas.pack(side="left", fill="both", expand=True, padx=30, pady=20)
        scrollbar.pack(side="right", fill="y")
        
        # Info box
        info_frame = tk.Frame(scrollable_frame, bg='#e3f2fd', relief=tk.SOLID, bd=1)
        info_frame.pack(fill=tk.X, pady=10, padx=5)
        
        info = tk.Label(info_frame, 
                       text="Safe testing mode - no system changes",
                       justify=tk.LEFT,
                       bg='#e3f2fd',
                       fg='#01579b',
                       font=("Arial", 9),
                       padx=15, pady=15)
        info.pack()
        
        # Passphrase entry section
        entry_frame = tk.Frame(scrollable_frame, bg='#e8f5e9')
        entry_frame.pack(pady=15)
        
        tk.Label(entry_frame, text="Test Passphrase:", bg='#e8f5e9', 
                font=("Arial", 10, "bold")).grid(row=0, column=0, padx=5, pady=8, sticky='e')
        self.pass_entry = tk.Entry(entry_frame, show="●", width=30, 
                                   font=("Arial", 11), relief=tk.SOLID, bd=1)
        self.pass_entry.grid(row=0, column=1, padx=5, pady=8)
        
        tk.Label(entry_frame, text="Confirm:", bg='#e8f5e9',
                font=("Arial", 10, "bold")).grid(row=1, column=0, padx=5, pady=8, sticky='e')
        self.confirm_entry = tk.Entry(entry_frame, show="●", width=30,
                                      font=("Arial", 11), relief=tk.SOLID, bd=1)
        self.confirm_entry.grid(row=1, column=1, padx=5, pady=8)
        
        # Show/hide checkbox
        self.show_var = tk.BooleanVar()
        show_check = tk.Checkbutton(entry_frame, text="Show passphrase", 
                                   variable=self.show_var,
                                   command=self.toggle_show,
                                   bg='#e8f5e9',
                                   font=("Arial", 9))
        show_check.grid(row=2, column=1, sticky='w', pady=5)
        
        # Strength indicator
        self.strength_label = tk.Label(entry_frame, text="", bg='#e8f5e9',
                                      font=("Arial", 9, "italic"))
        self.strength_label.grid(row=3, column=1, sticky='w')
        
        self.pass_entry.bind('<KeyRelease>', self.check_strength)
        
        # Buttons
        btn_frame = tk.Frame(scrollable_frame, bg='#e8f5e9')
        btn_frame.pack(pady=20)
        
        # Create test button
        test_btn = tk.Button(btn_frame, text="Create Test Passphrase", 
                            command=self.setup_test, 
                            width=25, 
                            bg="#4caf50", 
                            fg="white", 
                            font=("Arial", 11, "bold"),
                            relief=tk.RAISED, 
                            bd=2, 
                            pady=10,
                            cursor="hand2")
        test_btn.grid(row=0, column=0, padx=10, pady=5)
        
        # Test lock screen button
        self.test_lock_btn = tk.Button(btn_frame, text="Test Lock Screen", 
                                       command=self.test_lock_screen,
                                       width=25,
                                       bg="#2196f3",
                                       fg="white",
                                       font=("Arial", 11, "bold"),
                                       relief=tk.RAISED,
                                       bd=2,
                                       pady=10,
                                       cursor="hand2",
                                       state='disabled')
        self.test_lock_btn.grid(row=1, column=0, padx=10, pady=5)
        
        # Exit button
        exit_btn = tk.Button(btn_frame, text="Exit", 
                            command=self.root.quit, 
                            width=25, 
                            bg="#757575", 
                            fg="white",
                            font=("Arial", 10),
                            relief=tk.RAISED, 
                            bd=2, 
                            pady=8,
                            cursor="hand2")
        exit_btn.grid(row=2, column=0, padx=10, pady=15)
        
        # Check if already configured
        if self.guard.is_configured():
            self.test_lock_btn.config(state='normal')
            
            existing_label = tk.Label(scrollable_frame,
                                     text="✓ Test passphrase configured",
                                     bg='#e8f5e9',
                                     fg='#2e7d32',
                                     font=("Arial", 9, "italic"))
            existing_label.pack(pady=5)
    
    def toggle_show(self):
        if self.show_var.get():
            self.pass_entry.config(show="")
            self.confirm_entry.config(show="")
        else:
            self.pass_entry.config(show="●")
            self.confirm_entry.config(show="●")
    
    def check_strength(self, event=None):
        passphrase = self.pass_entry.get()
        if not passphrase:
            self.strength_label.config(text="", fg="black")
            return
        
        strength = 0
        if len(passphrase) >= 8:
            strength += 1
        if len(passphrase) >= 12:
            strength += 1
        if any(c.isupper() for c in passphrase):
            strength += 1
        if any(c.isdigit() for c in passphrase):
            strength += 1
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in passphrase):
            strength += 1
        
        if strength <= 2:
            self.strength_label.config(text="Strength: Weak", fg="#e53935")
        elif strength <= 3:
            self.strength_label.config(text="Strength: Medium", fg="#fb8c00")
        else:
            self.strength_label.config(text="Strength: Strong ✓", fg="#43a047")
    
    def setup_test(self):
        passphrase = self.pass_entry.get()
        confirm = self.confirm_entry.get()
        
        if not passphrase or not confirm:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if passphrase != confirm:
            messagebox.showerror("Error", "Passphrases do not match")
            return
        
        if len(passphrase) < 4:  # Relaxed for testing
            messagebox.showwarning("Warning", "For real deployment, use 8+ characters")
        
        # Generate and save hash
        hashed = self.guard.hash_passphrase(passphrase)
        
        if self.guard.save_test_hash(hashed):
            message = "✓ Test Passphrase Created!\n\n"
            message += f"• Hash: {hashed[:16]}...\n"
            message += f"• Stored in: {self.guard.test_dir}\n"
            message += "• Algorithm: SHA-256\n\n"
            message += "You can now test the lock screen!\n"
            message += "(Click 'Test Lock Screen' button)"
            
            messagebox.showinfo("Test Setup Complete", message)
            
            # Enable test lock button
            self.test_lock_btn.config(state='normal')
        else:
            messagebox.showerror("Error", "Failed to save test configuration")
    
    def test_lock_screen(self):
        """Open the lock screen test"""
        self.root.withdraw()  # Hide setup window
        test_lock = TestLockGUI(self.guard, self.root)
        test_lock.run()
    
    def run(self):
        self.root.mainloop()


class TestLockGUI:
    def __init__(self, guard, parent_window):
        self.guard = guard
        self.parent = parent_window
        self.root = tk.Toplevel()
        self.root.title("KeyGuard Lock Screen Test")
        self.root.attributes('-topmost', True)
        self.root.attributes('-fullscreen', True)
        self.root.configure(bg='#1a1a1a')
        
        # Allow ESC to exit test mode
        self.root.bind('<Escape>', self.exit_test)
        
        self.attempts = 0
        self.max_attempts = 3  # Fewer for testing
        
        self.create_widgets()
    
    def create_widgets(self):
        # Test mode banner
        banner = tk.Frame(self.root, bg='#4caf50', height=40)
        banner.pack(fill=tk.X, side=tk.TOP)
        
        banner_label = tk.Label(banner, 
                               text="🧪 TEST MODE - Press ESC to exit anytime",
                               font=("Arial", 12, "bold"),
                               bg='#4caf50',
                               fg='white')
        banner_label.pack(pady=10)
        
        # Main container
        container = tk.Frame(self.root, bg='#1a1a1a')
        container.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        # Lock icon
        icon = tk.Label(container, text="🔒", font=("Arial", 72), 
                       bg='#1a1a1a', fg='#ffffff')
        icon.pack(pady=20)
        
        # Title
        title = tk.Label(container, text="System Locked (TEST)", 
                        font=("Arial", 28, "bold"),
                        bg='#1a1a1a', fg='#ffffff')
        title.pack(pady=10)
        
        # Subtitle
        subtitle = tk.Label(container, 
                          text="Testing KeyGuard Authentication\nEnter your test passphrase",
                          font=("Arial", 12),
                          bg='#1a1a1a', fg='#cccccc')
        subtitle.pack(pady=10)
        
        # Test mode info
        info = tk.Label(container,
                       text="🧪 This is a simulation - Your system is NOT actually locked",
                       font=("Arial", 10, "italic"),
                       bg='#1a1a1a', fg='#4caf50')
        info.pack(pady=5)
        
        # Passphrase entry
        entry_frame = tk.Frame(container, bg='#1a1a1a')
        entry_frame.pack(pady=30)
        
        self.pass_entry = tk.Entry(entry_frame, show="●", width=30,
                                   font=("Arial", 14), bg='#2d2d2d',
                                   fg='#ffffff', insertbackground='#ffffff',
                                   relief=tk.FLAT, bd=10)
        self.pass_entry.pack()
        self.pass_entry.focus_set()
        self.pass_entry.bind('<Return>', lambda e: self.verify())
        
        # Unlock button
        tk.Button(container, text="🔓 Test Unlock", command=self.verify,
                 font=("Arial", 12, "bold"), width=20,
                 bg='#4caf50', fg='white', relief=tk.FLAT,
                 bd=0, pady=12, cursor="hand2").pack(pady=20)
        
        # Status label
        self.status_label = tk.Label(container, text="", 
                                    font=("Arial", 10),
                                    bg='#1a1a1a', fg='#e74c3c')
        self.status_label.pack(pady=10)
        
        # Attempts indicator
        self.attempts_label = tk.Label(container,
                                      text=f"Test attempts remaining: {self.max_attempts}",
                                      font=("Arial", 9),
                                      bg='#1a1a1a', fg='#7f8c8d')
        self.attempts_label.pack(pady=5)
        
        # Exit test button
        exit_btn = tk.Button(container, text="Exit Test (ESC)",
                            command=self.exit_test,
                            font=("Arial", 9),
                            bg='#757575',
                            fg='white',
                            relief=tk.FLAT,
                            bd=0,
                            pady=5,
                            cursor="hand2")
        exit_btn.pack(pady=20)
    
    def verify(self):
        passphrase = self.pass_entry.get()
        
        if self.guard.verify_passphrase(passphrase):
            self.status_label.config(text="✓ Correct! Authentication Successful", fg='#4caf50')
            messagebox.showinfo("Test Successful",
                              "✓ Passphrase verified correctly!\n\n"
                              "The authentication system is working.\n"
                              "In real mode, this would unlock your system.")
            self.exit_test()
        else:
            self.attempts += 1
            remaining = self.max_attempts - self.attempts
            
            if remaining > 0:
                self.status_label.config(text=f"✗ Incorrect passphrase (this is expected if testing)")
                self.attempts_label.config(
                    text=f"Test attempts remaining: {remaining}",
                    fg='#e74c3c')
                self.pass_entry.delete(0, tk.END)
                self.pass_entry.focus_set()
            else:
                self.status_label.config(text="✗ Maximum test attempts", fg='#c0392b')
                self.attempts_label.config(text="Test limit reached - Press ESC", fg='#c0392b')
                messagebox.showinfo("Test Complete",
                                  "Maximum attempts reached in test mode.\n\n"
                                  "In real mode, system would remain locked\n"
                                  "until computer restart.")
    
    def exit_test(self, event=None):
        """Exit test mode and return to setup"""
        self.root.destroy()
        self.parent.deiconify()  # Show setup window again
    
    def run(self):
        self.root.mainloop()


def main():
    guard = KeyGuardTestMode()
    
    print("\n" + "="*60)
    print("KEYGUARD SAFE TEST MODE")
    print("="*60)
    print("\n✓ Running in SAFE mode")
    print("✓ No system modifications will be made")
    print("✓ Test files stored in:", guard.test_dir)
    print("\n" + "="*60 + "\n")
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--reset':
            if guard.delete_test_config():
                print("✓ Test configuration deleted")
                messagebox.showinfo("Reset", "Test configuration has been removed.")
            else:
                print("✗ Failed to delete test configuration")
            return
    
    # Show test setup GUI
    setup = TestSetupGUI(guard)
    
    # Add cleanup info
    print("\nTo clean up test files after testing:")
    print(f"  python {__file__} --reset")
    print(f"  Or delete: {guard.test_dir}\n")
    
    setup.run()
    
    print("\n✓ Test mode exited safely")


if __name__ == '__main__':
    main()
