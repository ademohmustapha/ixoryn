import yaml
import os
from core.errors import IXORYNError

CONFIG_FILE = "ixoryn.yaml"

class Config:
    _config = None

    @classmethod
    def load(cls):
        if cls._config is None:
            if not os.path.exists(CONFIG_FILE):
                raise IXORYNError("Configuration file missing (ixoryn.yaml).")

            with open(CONFIG_FILE, "r") as f:
                cls._config = yaml.safe_load(f)

        return cls._config

    @classmethod
    def get(cls, path, default=None):
        cfg = cls.load()
        for key in path.split("."):
            cfg = cfg.get(key, {})
        return cfg if cfg else default

