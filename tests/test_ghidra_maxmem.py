import ghidra_runner


def test_ghidra_env_unset_inherits():
    assert ghidra_runner._ghidra_env("") is None


def test_ghidra_env_sets_xmx(monkeypatch):
    monkeypatch.delenv("JAVA_TOOL_OPTIONS", raising=False)
    env = ghidra_runner._ghidra_env("5g")
    assert env["JAVA_TOOL_OPTIONS"] == "-Xmx5g"


def test_ghidra_env_replaces_existing_xmx_keeps_other_opts(monkeypatch):
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-Xmx2g -Dfoo=bar")
    env = ghidra_runner._ghidra_env("6G")
    assert env["JAVA_TOOL_OPTIONS"] == "-Dfoo=bar -Xmx6G"


def test_ghidra_env_invalid_value_ignored():
    assert ghidra_runner._ghidra_env("5gb; rm -rf /") is None
    assert ghidra_runner._ghidra_env("lots") is None
