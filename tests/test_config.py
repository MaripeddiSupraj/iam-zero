from iam_zero.shared import config


def test_load_config_does_not_mutate_defaults(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('[github]\ndefault_repo = "org/repo"\n')
    monkeypatch.setattr(config, "CONFIG_FILE", cfg_file)

    first = config.load_config()
    first["github"]["default_repo"] = "changed/in-memory"

    second = config.load_config()
    assert second["github"]["default_repo"] == "org/repo"
    assert config._DEFAULTS["github"]["default_repo"] == ""


def test_missing_config_returns_fresh_nested_defaults(tmp_path, monkeypatch):
    cfg_file = tmp_path / "missing.toml"
    monkeypatch.setattr(config, "CONFIG_FILE", cfg_file)

    first = config.load_config()
    first["aws"]["default_days"] = 1

    second = config.load_config()
    assert second["aws"]["default_days"] == 90
