"""Küçük, bağımlılıksız yardımcılar.

``defang_ioc``: analist güvenliği. Raporlarda/UI'da gösterilen IoC'ler (URL, IP,
domain, e-posta) tıklanabilir link veya otomatik çözülen host olmasın diye
"defang" edilir:

    http://evil.example.com/a  ->  hxxp://evil.example[.]com/a
    https://1.1.1.1:8443/x     ->  hxxps://1.1.1[.]1:8443/x
    198.51.100.7               ->  198.51.100[.]7
    user@evil.example.com      ->  user@evil.example[.]com

Kurallar:
  * ``http`` -> ``hxxp``, ``https`` -> ``hxxps`` (``ftp`` -> ``fxp``).
  * Host kısmındaki **son** nokta ``[.]`` olur; path/query'ye dokunulmaz.
  * İdempotent: zaten defang edilmiş değer tekrar değişmez.
  * Veritabanında ve state JSON'unda ham değer saklanır (LLM eşleştirmesi ve
    tekrar üretilebilirlik için); defang sadece **gösterim** katmanında yapılır.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

# Defang edilecek bulgu türleri (state.Finding.kind). registry/file dokunulmaz.
NETWORK_IOC_KINDS = frozenset({"url", "ip", "domain", "email"})

_SCHEME_MAP = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}

_URL_RE = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*)://(?P<rest>.*)$", re.DOTALL)
# [kullanıcı@]host(.tld)+[:port|/path|?q|#f]
_BARE_RE = re.compile(
    r"^(?P<user>[^@\s/:]+@)?(?P<host>[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)(?P<tail>[:/?#].*)?$",
    re.DOTALL,
)
# Serbest metindeki URL ve çıplak IPv4'ler
_TEXT_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`)\]]+", re.IGNORECASE)
_TEXT_IPV4_RE = re.compile(r"(?<![\w.\[])(?:\d{1,3}\.){3}\d{1,3}(?![\w\]]|\.\d)")


def _bracket_last_dot(host: str) -> str:
    """Host'taki son noktayı ``[.]`` yapar (nokta yoksa veya zaten defang ise aynen)."""
    if "[.]" in host or "." not in host:
        return host
    i = host.rfind(".")
    return host[:i] + "[.]" + host[i + 1:]


def _split_authority(rest: str) -> tuple[str, str]:
    """``rest`` -> (authority, tail); authority ilk ``/ ? #`` karakterine kadardır."""
    for i, ch in enumerate(rest):
        if ch in "/?#":
            return rest[:i], rest[i:]
    return rest, ""


def _defang_authority(authority: str) -> str:
    """``[user@]host[:port]`` içindeki host'u defang eder (IPv6 köşeli host'a dokunmaz)."""
    userinfo, at, hostport = authority.rpartition("@")
    prefix = f"{userinfo}@" if at else ""
    if hostport.startswith("["):  # [::1]:80
        return authority
    host, sep, port = hostport.partition(":")
    return prefix + _bracket_last_dot(host) + sep + port


def defang_ioc(ioc: str) -> str:
    """Tek bir IoC değerini defang eder; tanınmayan değerler aynen döner."""
    if not isinstance(ioc, str) or not ioc:
        return ioc

    m = _URL_RE.match(ioc)
    if m:
        scheme = m.group("scheme")
        scheme_out = _SCHEME_MAP.get(scheme.lower(), scheme)
        authority, tail = _split_authority(m.group("rest"))
        return f"{scheme_out}://{_defang_authority(authority)}{tail}"

    m = _BARE_RE.match(ioc)
    if m:
        return f"{m.group('user') or ''}{_bracket_last_dot(m.group('host'))}{m.group('tail') or ''}"
    return ioc


def defang_iocs(values: Iterable[Any] | None) -> list[Any]:
    """Liste halinde defang (``None`` -> ``[]``)."""
    return [defang_ioc(v) if isinstance(v, str) else v for v in (values or [])]


def defang_text(text: str) -> str:
    """Serbest metindeki URL'leri ve çıplak IPv4 adreslerini defang eder."""
    if not isinstance(text, str) or not text:
        return text
    text = _TEXT_URL_RE.sub(lambda m: defang_ioc(m.group(0)), text)
    return _TEXT_IPV4_RE.sub(lambda m: _bracket_last_dot(m.group(0)), text)


def defang_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Bulgu sözlüğünün kopyasını döndürür; ağ IoC türlerinde ``value`` defang edilir."""
    out = dict(finding)
    if str(out.get("kind", "")).lower() in NETWORK_IOC_KINDS:
        out["value"] = defang_ioc(out.get("value", ""))
    return out
