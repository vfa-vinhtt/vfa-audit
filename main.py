#!/usr/bin/env python3
"""Convenience entry point for running the scanner from a source checkout.

The real CLI lives in ``scanner/cli.py`` so it can be exposed as the installed
``vfa-audit`` console command (and bundled by PyInstaller). This shim keeps
``python main.py ...`` working when running directly from a cloned repository.
"""
from scanner.cli import main

if __name__ == "__main__":
    main()
