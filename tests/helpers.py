"""Shared test helpers: isolated working directory and config."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


class IsolatedWorkspace:
    """A temporary directory that becomes the process working directory.

    The engine resolves storage, config and log paths relative to the working
    directory, so each test gets a clean slate.
    """

    def __init__(self, api_port=18765, extra=None):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.previous = None
        self.api_port = api_port
        self.extra = extra or {}

    def __enter__(self):
        self.previous = os.getcwd()
        os.chdir(self.root)
        (self.root / "config").mkdir(exist_ok=True)
        settings = {"api": {"port": self.api_port}, "engine": {"version": "test"}}
        for section, values in self.extra.items():
            settings.setdefault(section, {}).update(values)
        (self.root / "config" / "ase.json").write_text(json.dumps(settings), "utf-8")
        return self.root

    def __exit__(self, *exc_info):
        if self.previous:
            os.chdir(self.previous)
        self.temp.cleanup()
        return False
