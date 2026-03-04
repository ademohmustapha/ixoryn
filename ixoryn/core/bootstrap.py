"""
Ixoryn Bootstrap
Initializes runtime environment, directories, and configuration.
"""

import os
import sys
import json
import platform
from pathlib import Path


class Bootstrap:
    def __init__(self):
        self.home_dir = Path.home() / ".ixoryn"
        self.config_file = self.home_dir / "config.json"
        self.logs_dir = self.home_dir / "logs"
        self.output_dir = self.home_dir / "output"
        self.wordlists_dir = self.home_dir / "wordlists"
        self.temp_dir = self.home_dir / "temp"

    def initialize(self):
        """Set up all required directories and configs."""
        dirs = [
            self.home_dir,
            self.logs_dir,
            self.output_dir,
            self.wordlists_dir,
            self.temp_dir,
            self.output_dir / "crypto",
            self.output_dir / "stego",
            self.output_dir / "url_audit",
            self.output_dir / "password",
        ]

        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

        if not self.config_file.exists():
            self._create_default_config()

        # Set environment variable for tool base dir
        os.environ["IXORYN_HOME"] = str(self.home_dir)
        os.environ["IXORYN_OUTPUT"] = str(self.output_dir)

    def _create_default_config(self):
        config = {
            "version": "1.0",
            "platform": platform.system(),
            "logging": True,
            "log_level": "INFO",
            "output_dir": str(self.output_dir),
            "temp_dir": str(self.temp_dir),
            "url_audit": {
                "timeout": 10,
                "max_redirects": 5,
                "verify_ssl": True,
                "user_agent": "Ixoryn-Security-Auditor/1.0"
            },
            "password_audit": {
                "crack_time_assumptions": {
                    "online_throttled": 100,
                    "online_unthrottled": 10000,
                    "offline_slow_hash": 10000,
                    "offline_fast_hash": 10000000000
                }
            },
            "crypto": {
                "argon2id_time_cost": 3,
                "argon2id_memory_cost": 65536,
                "argon2id_parallelism": 4
            },
            "api_keys": {
                # SECURITY: Do NOT store API keys in this file.
                # Set environment variables instead:
                #   IXORYN_VT_KEY, IXORYN_ABUSEIPDB_KEY, IXORYN_SHODAN_KEY,
                #   IXORYN_OTX_KEY, IXORYN_HIBP_KEY, IXORYN_GSB_KEY
                # Values here are empty placeholders only.
                "virustotal": "",
                "abuseipdb": "",
                "google_safe_browsing": "",
                "shodan": "",
                "otx": "",
                "hibp": ""
            },
            "network_scanner": {
                "timeout": 2.0,
                "max_threads": 150
            },
            "version": "1.0"
        }
        with open(self.config_file, "w") as f:
            json.dump(config, f, indent=2)

    @staticmethod
    def load_config() -> dict:
        """Load config from default location (static method)."""
        import pathlib
        config_file = pathlib.Path.home() / ".ixoryn" / "config.json"
        try:
            with open(config_file, "r") as f:
                config = __import__("json").load(f)
        except Exception:
            config = {}
        return config

    @staticmethod
    def get_api_key(service: str) -> str:
        """
        Retrieve an API key - environment variables take priority over config file.
        This prevents accidental plaintext storage of credentials.

        Environment variable names:
          virustotal       -> IXORYN_VT_KEY
          abuseipdb        -> IXORYN_ABUSEIPDB_KEY
          google_safe_browsing -> IXORYN_GSB_KEY
          shodan           -> IXORYN_SHODAN_KEY
          otx              -> IXORYN_OTX_KEY
          hibp             -> IXORYN_HIBP_KEY
        """
        import os
        env_map = {
            "virustotal": "IXORYN_VT_KEY",
            "abuseipdb": "IXORYN_ABUSEIPDB_KEY",
            "google_safe_browsing": "IXORYN_GSB_KEY",
            "shodan": "IXORYN_SHODAN_KEY",
            "otx": "IXORYN_OTX_KEY",
            "hibp": "IXORYN_HIBP_KEY",
        }
        # Check env var first
        env_key = env_map.get(service.lower())
        if env_key:
            val = os.environ.get(env_key, "")
            if val:
                return val
        # Fall back to config file (may be empty)
        config = Bootstrap.load_config()
        return config.get("api_keys", {}).get(service, "")

    def get_config(self) -> dict:
        try:
            with open(self.config_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}
