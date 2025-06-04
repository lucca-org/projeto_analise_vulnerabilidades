#!/usr/bin/env python3
import os
import sys
import ctypes
import subprocess

print("DEBUG: Starting debug script...")

try:
    print("DEBUG: About to call ctypes.CDLL(None).geteuid()...")
    euid = ctypes.CDLL(None).geteuid()
    print(f"DEBUG: Successfully got euid: {euid}")
except Exception as e:
    print(f"DEBUG: geteuid failed with error: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

print("DEBUG: Script completed.")
