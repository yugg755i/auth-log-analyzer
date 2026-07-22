import pytest

from log_analyzer.config import DEFAULTS, ConfigError, load_config


def test_load_config_returns_defaults_when_no_file_and_none_given(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert load_config(None) == DEFAULTS


def test_load_config_merges_partial_yaml_over_defaults(tmp_path):
    config_file = tmp_path / "custom.yaml"
    config_file.write_text("bruteforce_threshold: 10\n")

    config = load_config(str(config_file))

    assert config["bruteforce_threshold"] == 10

    assert config["enum_threshold"] == DEFAULTS["enum_threshold"]


def test_load_config_auto_discovers_loganalyzer_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "loganalyzer.yaml").write_text("confidence_threshold: 75\n")

    config = load_config(None)

    assert config["confidence_threshold"] == 75


def test_load_config_missing_explicit_path_raises():
    with pytest.raises(ConfigError):
        load_config("/nonexistent/path/loganalyzer.yaml")


def test_load_config_unknown_key_raises(tmp_path):
    config_file = tmp_path / "bad.yaml"
    config_file.write_text("typo_threshold: 10\n")

    with pytest.raises(ConfigError):
        load_config(str(config_file))


def test_load_config_empty_file_returns_defaults(tmp_path):
    config_file = tmp_path / "empty.yaml"
    config_file.write_text("")

    assert load_config(str(config_file)) == DEFAULTS


def test_load_config_rejects_non_mapping_yaml(tmp_path):
    config_file = tmp_path / "list.yaml"
    config_file.write_text("- 1\n- 2\n")

    with pytest.raises(ConfigError):
        load_config(str(config_file))
