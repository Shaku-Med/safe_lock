"""Secure temp viewing: decrypt to a locked-down temp dir, open, then overwrite-and-wipe.

Identity verification is best-effort per OS (Windows Hello, macOS Touch ID, Linux polkit),
falling back to the Steal Locker device-key passphrase. The real protection is always the
encryption itself; verification gates the convenience flow.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

VERIFY_REASON = "Unlock file with Safe Lock"


# --- identity verification providers (each returns True/False, or None if unavailable) ---

def _verify_windows_hello() -> bool | None:
    if os.name != "nt":
        return None
    try:
        import asyncio
        from winsdk.windows.security.credentials.ui import (
            UserConsentVerifier, UserConsentVerifierAvailability, UserConsentVerificationResult,
        )
    except ImportError:
        return None

    async def _run():
        availability = await UserConsentVerifier.check_availability_async()
        if availability != UserConsentVerifierAvailability.AVAILABLE:
            return None
        result = await UserConsentVerifier.request_verification_async(VERIFY_REASON)
        return result == UserConsentVerificationResult.VERIFIED

    try:
        return asyncio.run(_run())
    except Exception:
        return None


def _verify_macos_touchid() -> bool | None:
    if sys.platform != "darwin":
        return None
    try:
        from LocalAuthentication import LAContext, LAPolicyDeviceOwnerAuthentication
    except ImportError:
        return None
    import threading
    try:
        ctx = LAContext.new()
        ok, _ = ctx.canEvaluatePolicy_error_(LAPolicyDeviceOwnerAuthentication, None)
        if not ok:
            return None
        done = threading.Event()
        outcome = {}

        def reply(success, error):
            outcome["ok"] = bool(success)
            done.set()

        ctx.evaluatePolicy_localizedReason_reply_(LAPolicyDeviceOwnerAuthentication, VERIFY_REASON, reply)
        done.wait(timeout=120)
        return outcome.get("ok", False)
    except Exception:
        return None


def _verify_linux_polkit() -> bool | None:
    if not sys.platform.startswith("linux"):
        return None
    if shutil.which("pkexec") is None:
        return None
    try:
        # polkit prompts for the user's password via the desktop agent; exit 0 = authenticated.
        rc = subprocess.run(["pkexec", "true"], capture_output=True, timeout=180).returncode
        return rc == 0
    except Exception:
        return None


def _verify_device_key_passphrase() -> bool | None:
    """Cross-platform fallback: loading a passphrase-protected Steal Locker device key proves identity."""
    from steal_locker.key import _key_dir, load_private_key
    priv_path = _key_dir() / "key.private"
    if not priv_path.exists():
        return None
    try:
        raw = priv_path.read_bytes()
        if not raw.strip().startswith(b"{"):
            # Unencrypted device key proves device possession only, not identity.
            return None
        load_private_key(priv_path)
        return True
    except Exception:
        return False


_PROVIDERS = [
    ("Windows Hello (device PIN / biometrics)", _verify_windows_hello),
    ("macOS Touch ID / device password", _verify_macos_touchid),
    ("Linux polkit (account password)", _verify_linux_polkit),
    ("Steal Locker device-key passphrase", _verify_device_key_passphrase),
]


def verify_device_identity() -> bool:
    """Try providers in order; first one that is available decides. No provider = ask user."""
    for name, provider in _PROVIDERS:
        result = provider()
        if result is None:
            continue
        if result:
            print(f"✓ Identity verified ({name})")
            return True
        print(f"✗ Verification failed ({name})")
        return False
    print("\n⚠ No identity verifier is available on this system.")
    print("  Windows: pip install winsdk (Windows Hello)")
    print("  macOS:   pip install pyobjc-framework-LocalAuthentication (Touch ID)")
    print("  Any OS:  set a passphrase on your Steal Locker device key")
    proceed = input("Continue without device verification? (y/n): ").strip().lower()
    return proceed == "y"


# --- temp viewing and wiping ---

def _open_with_default_app(path: str):
    if os.name == "nt":
        os.startfile(path)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


def _overwrite_file(path: str):
    """Overwrite contents with random bytes before deletion. Best-effort on SSDs (wear leveling)."""
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        f.write(os.urandom(size))
        f.flush()
        os.fsync(f.fileno())


def wipe_directory(dir_path: str, retries: int = 5, delay: float = 1.0) -> bool:
    """Overwrite and delete every file in dir_path, then remove it. Retries while apps hold locks."""
    for attempt in range(retries):
        try:
            for root, _, names in os.walk(dir_path):
                for name in names:
                    p = os.path.join(root, name)
                    _overwrite_file(p)
                    os.remove(p)
            shutil.rmtree(dir_path, ignore_errors=False)
            return True
        except OSError:
            if attempt == retries - 1:
                return False
            time.sleep(delay)
    return False


def view_file_temp(data: bytes, filename: str, launch: bool = True):
    """Write data to a private temp dir, optionally open with the default app, then wipe."""
    tmp_dir = tempfile.mkdtemp(prefix="safelock_")
    path = os.path.join(tmp_dir, filename)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    try:
        if launch:
            _open_with_default_app(path)
            print(f"\n✓ File opened: {filename}")
        else:
            print(f"\n✓ File extracted to temp: {path}")
        print("⚠ The file will be wiped when you continue.")
        input("Press Enter when you finish viewing (close the app first)... ")
    finally:
        while not wipe_directory(tmp_dir):
            print(f"\n⚠ Could not wipe temp file (still in use?): {path}")
            choice = input("Close the viewing app, then press Enter to retry (or type 'leave' to keep it): ").strip().lower()
            if choice == "leave":
                print(f"⚠ File NOT wiped. Delete it manually: {path}")
                return
        print("✓ Temp file securely wiped.")
