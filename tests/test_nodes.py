"""nodes.py içindeki saf (dış araç gerektirmeyen) mantık için birim testleri."""

from __future__ import annotations

import pytest

from nodes import _collect_floss_strings, filter_iocs, summarize_capa


# --------------------------------------------------------------------------- #
# filter_iocs
# --------------------------------------------------------------------------- #
class TestFilterIocs:
    @pytest.mark.parametrize(
        "text",
        [
            # URL'ler
            "http://evil.com/a",
            "https://evil.com/payload.bin",
            "tcp://1.2.3.4:4444",
            "HTTP://EVIL.COM",  # büyük/küçük harf duyarsız
            # IPv4
            "10.0.0.1",
            "connect to 192.168.1.255 now",
            "255.255.255.255",
            # Dosya uzantıları
            "C:\\Windows\\Temp\\a.dll",
            "malware.exe",
            "driver.sys",
            "run.bat",
            "script.PS1",
            "dropper.vbs",
            "screen.scr",
            "shortcut.lnk",
            # Registry
            "HKLM\\Software\\Run",
            "HKCU\\Software\\Classes",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ],
    )
    def test_keeps_iocs(self, text: str) -> None:
        assert filter_iocs([text]) == [text]

    @pytest.mark.parametrize(
        "text",
        [
            "hello world",
            "",
            "   ",
            "1.2.3.4.5",  # sürüm numarası
            "999.1.1.1",  # geçersiz oktet
            "256.256.256.256",
            "x.dllfoo",  # uzantı kelimenin parçası
            ".exe",  # dosya adı yok
            "aaaaaaaaaaaaaaaa",
            "ftp://example.com",  # istenen şemalar dışında
        ],
    )
    def test_drops_garbage(self, text: str) -> None:
        assert filter_iocs([text]) == []

    def test_deduplicates_and_preserves_order(self) -> None:
        data = ["b.exe", "http://a.com", "b.exe", "noise", "http://a.com", "1.1.1.1"]
        assert filter_iocs(data) == ["b.exe", "http://a.com", "1.1.1.1"]

    def test_empty_input(self) -> None:
        assert filter_iocs([]) == []

    def test_ignores_non_string_items(self) -> None:
        assert filter_iocs(["a.exe", None, 42, {"x": 1}]) == ["a.exe"]  # type: ignore[list-item]


# --------------------------------------------------------------------------- #
# _collect_floss_strings
# --------------------------------------------------------------------------- #
class TestCollectFlossStrings:
    def test_collects_decoded_stack_and_static(self) -> None:
        report = {
            "strings": {
                "static_strings": [{"string": "http://static.com"}],
                "decoded_strings": [{"string": "10.0.0.1"}],
                "stack_strings": [{"string": "a.exe"}],
                "tight_strings": [{"string": "tight.dll"}],
            }
        }
        pool = _collect_floss_strings(report)
        # static is included (run_floss filters it with filter_iocs); tight is not.
        assert pool == ["10.0.0.1", "a.exe", "http://static.com"]
        assert "tight.dll" not in pool

    def test_accepts_plain_strings_and_dicts(self) -> None:
        report = {"strings": {"decoded_strings": ["plain.bat"], "stack_strings": [{"string": "b.exe"}]}}
        assert _collect_floss_strings(report) == ["plain.bat", "b.exe"]

    def test_falls_back_to_root_level_keys(self) -> None:
        report = {"decoded_strings": [{"string": "root.dll"}], "stack_strings": []}
        assert _collect_floss_strings(report) == ["root.dll"]

    def test_skips_malformed_entries(self) -> None:
        report = {
            "strings": {
                "decoded_strings": [{"no_string_key": 1}, None, 5, {"string": 123}, {"string": "ok.exe"}],
                "stack_strings": "not a list",
            }
        }
        assert _collect_floss_strings(report) == ["ok.exe"]

    @pytest.mark.parametrize("report", [{}, {"strings": None}, {"strings": []}, {"strings": {}}])
    def test_empty_or_unexpected_structure(self, report: dict) -> None:
        assert _collect_floss_strings(report) == []

    def test_output_feeds_filter_iocs(self) -> None:
        report = {
            "strings": {
                "decoded_strings": [{"string": "http://c2.example/x"}, {"string": "garbage"}],
                "stack_strings": [{"string": "cmd /c run.bat"}, {"string": "http://c2.example/x"}],
            }
        }
        assert filter_iocs(_collect_floss_strings(report)) == ["http://c2.example/x", "cmd /c run.bat"]


# --------------------------------------------------------------------------- #
# summarize_capa
# --------------------------------------------------------------------------- #
ATTACK_ENTRY = {
    "parsed": ["Defense Evasion", "Process Injection::Process Hollowing", "T1055.012"],
    "tactic": "Defense Evasion",
    "technique": "Process Injection",
    "subtechnique": "Process Hollowing",
    "id": "T1055.012",
}
MBC_ENTRY = {
    "parsed": ["Anti-Behavioral Analysis", "Debugger Detection::Software Breakpoints", "B0001.025"],
    "id": "B0001.025",
    "objective": "Anti-Behavioral Analysis",
    "behavior": "Debugger Detection",
    "method": "Software Breakpoints",
}


class TestSummarizeCapa:
    def test_extracts_rules_attack_and_mbc(self) -> None:
        report = {
            "meta": {"huge": "ignored"},
            "rules": {
                "inject process": {
                    "meta": {"attack": [ATTACK_ENTRY], "mbc": [MBC_ENTRY]},
                    "source": "...",
                    "matches": {"0x401000": [{"huge": "tree"}]},
                },
                "create registry key": {"meta": {}, "matches": {}},
            },
        }
        assert summarize_capa(report) == {
            "matched_rules": ["inject process", "create registry key"],
            "mitre_attack": ["T1055.012 - Process Injection::Process Hollowing (Defense Evasion)"],
            "malware_behavior": ["B0001.025 - Debugger Detection::Software Breakpoints (Anti-Behavioral Analysis)"],
        }

    def test_output_has_exactly_the_three_keys(self) -> None:
        assert set(summarize_capa({})) == {"matched_rules", "mitre_attack", "malware_behavior"}

    def test_does_not_leak_match_trees(self) -> None:
        report = {"rules": {"r": {"meta": {}, "matches": {"0x1": ["secret-tree"]}}}}
        assert "secret-tree" not in str(summarize_capa(report))

    def test_deduplicates_across_rules(self) -> None:
        report = {
            "rules": {
                "rule a": {"meta": {"attack": [ATTACK_ENTRY], "mbc": [MBC_ENTRY]}},
                "rule b": {"meta": {"attack": [ATTACK_ENTRY], "mbc": [MBC_ENTRY]}},
            }
        }
        result = summarize_capa(report)
        assert result["matched_rules"] == ["rule a", "rule b"]
        assert len(result["mitre_attack"]) == 1
        assert len(result["malware_behavior"]) == 1

    def test_technique_without_subtechnique(self) -> None:
        entry = {"id": "T1059", "tactic": "Execution", "technique": "Command and Scripting Interpreter", "subtechnique": ""}
        result = summarize_capa({"rules": {"r": {"meta": {"attack": [entry]}}}})
        assert result["mitre_attack"] == ["T1059 - Command and Scripting Interpreter (Execution)"]

    def test_legacy_string_entries(self) -> None:
        legacy = "Defense Evasion::Process Injection [T1055]"
        result = summarize_capa({"rules": {"r": {"meta": {"attack": [legacy], "mbc": ["Anti-Analysis::Debugger"]}}}})
        assert result["mitre_attack"] == [legacy]
        assert result["malware_behavior"] == ["Anti-Analysis::Debugger"]

    def test_falls_back_to_parsed_when_fields_missing(self) -> None:
        entry = {"parsed": ["Execution", "Shell", "T9999"]}
        result = summarize_capa({"rules": {"r": {"meta": {"attack": [entry]}}}})
        assert result["mitre_attack"] == ["Execution :: Shell :: T9999"]

    @pytest.mark.parametrize(
        "report",
        [
            {},
            {"rules": None},
            {"rules": []},
            {"rules": "nope"},
            {"meta": {}},
        ],
    )
    def test_missing_or_unexpected_rules_key(self, report: dict) -> None:
        assert summarize_capa(report) == {"matched_rules": [], "mitre_attack": [], "malware_behavior": []}

    def test_malformed_rule_entries_do_not_crash(self) -> None:
        report = {
            "rules": {
                "int rule": 5,
                "none rule": None,
                "meta not dict": {"meta": "x"},
                "attack not list": {"meta": {"attack": "T1055", "mbc": None}},
                "bad entries": {"meta": {"attack": [None, 5, {}, {"id": ""}], "mbc": [[]]}},
                "good": {"meta": {"attack": [ATTACK_ENTRY]}},
            }
        }
        result = summarize_capa(report)
        assert result["matched_rules"] == [
            "int rule",
            "none rule",
            "meta not dict",
            "attack not list",
            "bad entries",
            "good",
        ]
        assert result["mitre_attack"] == ["T1055.012 - Process Injection::Process Hollowing (Defense Evasion)"]
        assert result["malware_behavior"] == []
