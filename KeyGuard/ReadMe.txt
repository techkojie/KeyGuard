## 🚀 Download & Run (No Installation Needed)

1. Download `keyguard.exe` from this repository
2. Double-click it (run as Administrator when prompted)
3. Follow the setup — write down your passphrase AND recovery code!
4. Reboot to test

→ Always try `keyguard_test_mode.py` first if you're unsure!

KeyGuard - Instant Windows Boot Lock with Recovery EXTREME CAUTION: This tool locks your Windows PC instantly on boot — before the desktop appears.
You will not be able to use your computer until you enter the correct passphrase (or your one-time recovery code).
Forgetting both the passphrase and recovery code will require a full Windows reinstall.Use only if you fully understand the risk. Always test with the safe mode first!What is KeyGuard?KeyGuard is a lightweight, open-source Windows boot-time authentication system written in Python. It provides strong physical-access protection by:Locking the system instantly on startup (zero delay)
Killing explorer.exe (no desktop/taskbar)
Disabling Task Manager and Registry Editor
Showing a clean fullscreen lock screen
Requiring your passphrase to unlock

It includes a safe one-time recovery code shown only during setup — if you forget your main passphrase, you can use this code once to regain access (it is then permanently disabled for security).Repository Contentskeyguard_test_mode.py → SAFE TEST VERSION (highly recommended first!)No system changes
Stores test data in your home folder
Lets you practice the full lock screen experience safely
Press ESC anytime to exit

keyguard.py → REAL INSTANT BOOT LOCK (use with extreme care)Full protection with recovery code
Stores encrypted hash in protected system location + registry backup
Adds itself to startup for instant activation on boot

keyguard.exe → Standalone executable (coming soon / already included)No Python installation required
Perfect for non-technical users
Same functionality as keyguard.py

RequirementsFor running the Python files (.py):Windows 10 or 11 (64-bit recommended)
Python 3.8+ installed
Run as Administrator (required for registry/startup changes)

For the .exe version:Windows 10 or 11
No Python needed
Just double-click (will prompt for admin rights)

How to UseStep 1: ALWAYS START WITH TEST MODEbash

python keyguard_test_mode.py

Set a test passphrase
Click "Test Lock Screen"
Practice entering it correctly (and incorrectly)
Make sure everything feels right
Close with ESC or Exit button

Step 2: Only then — Activate Real Protectionbash

python keyguard.py

Or double-click keyguard.exeFirst run:You’ll be guided through setup
Choose a strong passphrase (8+ characters)
WRITE DOWN BOTH:Your main passphrase
The 20-character one-time recovery code (shown only once!)

Confirm activation

After reboot:Your PC will boot to a black fullscreen lock screen
Enter your passphrase (or recovery code)
Correct entry → desktop appears normally
Wrong entry → attempts counter decreases (5 max)

Changing or DisablingRun keyguard.py or keyguard.exe again while logged in:Choose "Yes" to change passphrase (new recovery code generated)
Choose "No" to completely disable and remove KeyGuard

Emergency Removal (if locked out but have recovery code)Just enter the recovery code — it works once and disables itself.Manual Removal (if needed)If you can’t boot normally:Boot into Safe Mode
Delete folder: C:\ProgramData\KeyGuardRestrictor
Delete registry key: HKEY_CURRENT_USER\SOFTWARE\KeyGuardRestrictor
Delete startup entry: Check Task Manager → Startup tab, or remove KeyGuardRestrictor.vbs from Startup folder

Security NotesPassphrase is never stored in plain text — only SHA-256 hash with salt
Recovery code is one-time use only (burned after success)
No backdoors
Designed to resist casual physical attacks (theft, family/friends access)

DisclaimerThis tool is for advanced users who want strong local protection.
The author is not responsible for data loss, lockouts, or system issues.
Always keep your recovery code safe and separate from your main passphrase.Test thoroughly with keyguard_test_mode.py before activating real mode!Made with  for privacy and security
Open source • No telemetry • No nonsenseFeel free to star, fork, or contribute! Issues and suggestions welcome.

## Known Limitation: Multi-Monitor Setups

KeyGuard works best with a single monitor or duplicated displays.

In extended multi-monitor mode:
- Secondary monitors may remain partially accessible (mouse/keyboard input works).
- This reduces protection strength.

Recommendation: Use "Duplicate" mode (Win+P) for strongest security, or disconnect secondary monitors when high security is needed.
