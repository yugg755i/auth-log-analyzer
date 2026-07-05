from pathlib import Path

import yaml

DEFAULTS = {
    "bruteforce_threshold": 5,
    "bruteforce_window_minutes": 2,
    "enum_threshold": 5,
    "enum_window_minutes": 2,
    "confidence_threshold": 50,
}

AUTO_DISCOVER_FILENAME = "config/loganalyzer.yaml"


class ConfigError(Exception):
    """Raised for a malformed or invalid config file."""


def load_config(path=None):
    config = dict(DEFAULTS)

    if path is not None:
        config_path = Path(path)
        if not config_path.exists():
            raise ConfigError(f"config file not found: {path}")
    else:
        auto = Path(AUTO_DISCOVER_FILENAME)
        config_path = auto if auto.exists() else None

    if config_path is None:
        return config

    with open(config_path) as f:
        try:
            raw = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigError(f"could not parse {config_path}: {e}") from e

    raw = raw or {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{config_path} must be a mapping of setting: value")

    unknown = set(raw) - set(DEFAULTS)
    if unknown:
        raise ConfigError(
            f"unknown config key(s) in {config_path}: {', '.join(sorted(unknown))}"
        )

    config.update(raw)
    return config
