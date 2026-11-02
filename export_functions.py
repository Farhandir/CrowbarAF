# @category CrowbarAF
"""Ghidra analyzeHeadless -postScript betiği (PyGhidra / Python 3).

Argümanlar (sırayla): <ghidra_input_json_path> <out_json_path>

  ghidra_input.json:
    {"hints":      [{"offset": "0x401000", "rule": "..."}],          # capa adresleri
     "findings":   [{"source": "import_combo", "value": "...", ...}], # state.findings
     "combo_apis": {"Process Injection Combo": ["virtualalloc", ...]}}
  out.json: state.DecompiledFunction şemasına uygun sözlük listesi.

Mantık:
  1. Programdaki TÜM fonksiyonlar için ad, adres, size, callees ve priority hesaplanır
     (decompile yapılmaz; ucuzdur).
  2. Puanlama: capa hint +5, tehlikeli API +4, import combo API'si +4,
     çok büyük fonksiyon -2, kütüphane/stub = 0 (``is_library_heuristic``: thunk/external,
     ``__libc_``/``_Z``/``std::``/... önekleri, size < 16; is_library=True ve priority=0).
     İstisna: entry/main ve kanıt taşıyan (capa/IoC) fonksiyonlar ad/boyut sezgisiyle
     kütüphane sayılmaz (``SOFT_LIBRARY_REASONS``).
  3. Sadece en yüksek puanlı ilk MAX_DECOMPILE (100) fonksiyon decompile edilir.
     Puanlı fonksiyon yoksa en büyük birkaç fonksiyon (FALLBACK_DECOMPILE) denenir.
  4. Decompile edilenlerin doğrudan callee'leri ``c_code: ""`` ile (çağrı grafiği
     bağlansın diye) çıktıya eklenir; diğer yüzlerce fonksiyon çıktıya girmez.
  5. Adressiz IoC -> fonksiyon eşleme: ``findings``'teki ip/url/domain/registry/file/email
     değerleri, programın tanımlı string'lerinde aranır (eşit veya string'in içinde geçen);
     eşleşen string'e referans veren fonksiyonun ``iocs`` listesine değer eklenir ve
     fonksiyon +3 puan alır (IoC sayısından bağımsız, fonksiyon başına bir kez).

Not: Saf mantık (puanlama/seçim) Ghidra olmadan da import edilip test edilebilir;
``main()`` yalnızca Ghidra ortamında (``currentProgram`` varsa) çalışır.
"""

import json
import os

DECOMPILE_TIMEOUT_SECONDS = int(os.environ.get("CROWBAR_DECOMPILE_TIMEOUT", "60"))

CAPA_HIT_BONUS = 5
DANGEROUS_API_BONUS = 4
IMPORT_COMBO_BONUS = 4
LARGE_FUNCTION_BYTES = 10000
LARGE_FUNCTION_PENALTY = 2
IOC_REFERENCE_BONUS = 3  # fonksiyon bir IoC string'ine referans veriyorsa (kaç IoC olursa olsun bir kez)

# findings içinde string->fonksiyon eşlemesine girecek bulgu türleri
IOC_KINDS = ("ip", "url", "domain", "registry", "file", "email")
MIN_IOC_LENGTH = 4  # "a.b" gibi çok kısa değerler rastgele string'lerle eşleşmesin
MAX_TARGET_IOCS = 2000  # aranacak IoC üst sınırı (string sayısı x IoC sayısı patlamasın)
MAX_IOCS_PER_FUNCTION = 20
MAX_DEFINED_DATA = int(os.environ.get("CROWBAR_MAX_DEFINED_DATA", "2000000"))  # Listing fallback cap

MAX_DECOMPILE = int(os.environ.get("CROWBAR_MAX_DECOMPILE", "100"))  # Top-N
FALLBACK_DECOMPILE = int(os.environ.get("CROWBAR_FALLBACK_DECOMPILE", "20"))
MAX_STUBS = 500  # c_code'suz callee kayıtlarının üst sınırı

# Kütüphane/derleyici sezgisi (is_library_heuristic). Önek eşleşmesi büyük/küçük harf duyarlı.
LIBRARY_NAME_PREFIXES = (
    "__libc_", "_Z", "std::", "__cxa_", "__gxx_", "j_", "CRT_", "golang.", "runtime.",
)
MIN_FUNCTION_BYTES = 16  # daha küçükler: padding, thunk veya işlevsiz RET
# Sadece ad/boyut sezgisiyle (Ghidra bayrağı olmadan) kütüphane sayılan bir fonksiyon;
# entry/main ise veya kanıt taşıyorsa (capa / IoC) kütüphane SAYILMAZ: "_Z" ile başlayan
# kullanıcı C++ kodu ya da kısa ama IoC'ye referans veren fonksiyon sessizce 0'a düşmesin.
SOFT_LIBRARY_REASONS = frozenset(("prefix", "size"))
ENTRY_NAMES = frozenset(("main", "_start", "entry", "wmain"))
MAX_CALLEES = 50
MAX_XREFS = 50

# Küçük harfli, alt-dize eşleşmesi (CreateProcessA/W/Ex gibi varyantları da yakalar)
# Windows: substring match (CreateProcessA/W/Ex variants)
DANGEROUS_APIS_SUBSTRING = (
    "virtualalloc",
    "virtualprotect",
    "createprocess",
    "createremotethread",
    "writeprocessmemory",
    "readprocessmemory",
    "openprocess",
    "ntunmapviewofsection",
    "queueuserapc",
    "setwindowshookex",
    "internetopen",
    "internetconnect",
    "internetreadfile",
    "httpsendrequest",
    "urldownloadtofile",
    "winhttpopen",
    "winexec",
    "shellexecute",
    "cryptencrypt",
    "cryptdecrypt",
    "regsetvalue",
    "regcreatekey",
    "createservice",
)
# Linux: EXACT match ("clone" must not match "deregister_tm_clones")
DANGEROUS_APIS_EXACT = frozenset((
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "sendto",
    "recvfrom",
    "send",
    "recv",
    "execve",
    "execvp",
    "execl",
    "system",
    "popen",
    "fork",
    "clone",
    "dlopen",
    "dlsym",
    "ptrace",
    "mprotect",
    "mmap",
    "munmap",
    "prctl",
    "setuid",
    "setgid",
    "socketpair",
    "sendmsg",
    "recvmsg",
    "execv",
    "execvpe",
    "fexecve",
    "execlp",
    "execle",
    "vfork",
    "mmap64",
    "seteuid",
    "setegid",
))
# Union kept for external imports / backwards compatibility
DANGEROUS_APIS = tuple(DANGEROUS_APIS_SUBSTRING) + tuple(sorted(DANGEROUS_APIS_EXACT))


# --------------------------------------------------------------------------- #
# Saf mantık (Ghidra gerektirmez)
# --------------------------------------------------------------------------- #
def base_name(name):
    """'<EXTERNAL>::VirtualAlloc' -> 'virtualalloc'."""
    return str(name).split("::")[-1].strip().lower()


def active_combo_apis(findings, combo_apis):
    """Bulgulardaki import_combo kurallarının içerdiği API isimlerinin kümesi."""
    apis = set()
    for finding in findings:
        if isinstance(finding, dict) and finding.get("source") == "import_combo":
            for api in combo_apis.get(finding.get("value"), []):
                apis.add(str(api).lower())
    return apis


def collect_target_iocs(findings):
    """Bulgulardan (kind: ip/url/domain/registry/file/email) aranacak IoC değerlerinin kümesi."""
    targets = set()
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("kind") not in IOC_KINDS:
            continue
        value = finding.get("value")
        if isinstance(value, str) and len(value.strip()) >= MIN_IOC_LENGTH:
            targets.add(value.strip())
        if len(targets) >= MAX_TARGET_IOCS:
            break
    return targets


def build_ioc_index(target_iocs):
    """[(küçük_harf, orijinal), ...] — her string için yeniden küçültme yapılmasın."""
    return sorted((ioc.lower(), ioc) for ioc in target_iocs)


def match_iocs(text, ioc_index):
    """``text`` bir IoC'ye eşitse veya IoC'yi içeriyorsa eşleşen IoC'ler (orijinal yazımla).

    Büyük/küçük harf duyarsız (domain, registry yolu, URL). Ters yön (IoC içinde kısa string)
    bilerek aranmaz: kısa string'ler yanlış pozitif üretir.
    """
    lowered = str(text).lower()
    if len(lowered.strip()) < MIN_IOC_LENGTH:
        return []
    return [original for low, original in ioc_index if low in lowered]


def add_ioc_hits(hits, entry, iocs):
    """``hits[entry]`` listesine IoC'leri tekrarsız ekler (fonksiyon başına en fazla MAX_IOCS_PER_FUNCTION)."""
    bucket = hits.setdefault(entry, [])
    for ioc in iocs:
        if ioc not in bucket and len(bucket) < MAX_IOCS_PER_FUNCTION:
            bucket.append(ioc)


def _call(obj, method, default):
    """``obj.method()`` çağırır; yoksa/hata verirse ``default`` (Ghidra nesneleri bazen patlar)."""
    try:
        return getattr(obj, method)()
    except Exception:
        return default


def is_entry_name(name):
    """Giriş noktası/main benzeri ad (her zaman decompile edilir; kütüphane sayılmaz)."""
    return str(name or "").strip().lower() in ENTRY_NAMES


def library_reason(func, size):
    """Fonksiyonun neden kütüphane/stub sayıldığı: ``""`` (sayılmadı) ya da
    ``"thunk"`` | ``"external"`` | ``"prefix"`` | ``"size"`` (bu sırayla ilk eşleşen).
    """
    if _call(func, "isThunk", False):
        return "thunk"
    if _call(func, "isExternal", False):
        return "external"
    name = str(_call(func, "getName", "") or "")
    if name.startswith(LIBRARY_NAME_PREFIXES):
        return "prefix"
    try:
        if int(size) < MIN_FUNCTION_BYTES:
            return "size"
    except (TypeError, ValueError):
        pass
    return ""


def is_library_heuristic(func, size):
    """Kütüphane/derleyici/stub fonksiyonu mu? (``True`` => is_library, priority 0)

    ``True`` döner:
      * Ghidra bayrağı: ``func.isThunk()`` veya ``func.isExternal()``;
      * ad ``LIBRARY_NAME_PREFIXES`` öneklerinden biriyle başlıyorsa
        (``__libc_``, ``_Z``, ``std::``, ``__cxa_``, ``__gxx_``, ``j_``, ``CRT_``,
        ``golang.``, ``runtime.``);
      * ``size < 16`` byte (padding / thunk / işlevsiz RET).

    Saf sezgidir. Kanıt taşıyan fonksiyonlar için istisna ``collect_records``'tadır
    (``SOFT_LIBRARY_REASONS``).
    """
    return bool(library_reason(func, size))


def compute_priority(capa_hits, callee_names, size, is_library, combo_apis, ioc_hits=None):
    """Fonksiyon öncelik puanı (kütüphane/thunk her zaman 0).

    ``ioc_hits``: fonksiyonun string referansıyla kullandığı IoC'ler; doluysa +3 (bir kez).
    """
    if is_library:
        return 0

    priority = 0
    if capa_hits:
        priority += CAPA_HIT_BONUS
    if ioc_hits:
        priority += IOC_REFERENCE_BONUS

    names = [base_name(n) for n in callee_names]
    substring_hit = any(api in name for name in names for api in DANGEROUS_APIS_SUBSTRING)
    exact_hit = any(name in DANGEROUS_APIS_EXACT for name in names)
    if substring_hit or exact_hit:
        priority += DANGEROUS_API_BONUS
    if combo_apis and any(name in combo_apis for name in names):
        priority += IMPORT_COMBO_BONUS

    if size > LARGE_FUNCTION_BYTES:
        priority -= LARGE_FUNCTION_PENALTY
    return max(priority, 0)


def propagate_priority(records, hops=2):
    """Raise callees of high-priority functions (a wrapper may hide the payload)."""
    by_offset = {r["offset"]: r for r in records}
    for _ in range(max(1, hops)):
        changed = False
        for r in records:
            if (r.get("priority") or 0) <= 0:
                continue
            for callee in r.get("callees") or []:
                target = by_offset.get(callee)
                if target is None or target.get("is_library"):
                    continue
                new = max(target.get("priority") or 0, (r.get("priority") or 0) - 1)
                if new > (target.get("priority") or 0):
                    target["priority"] = new
                    changed = True
        if not changed:
            break


def plan_export(records):
    """Kayıt listesinden (decompile edilecekler, c_code'suz callee kayıtları) seçer.

    * priority > 0 olanlar, puana göre azalan (eşitlikte küçük fonksiyon önce), ilk MAX_DECOMPILE.
    * Hiç puanlı fonksiyon yoksa: kütüphane olmayan en büyük FALLBACK_DECOMPILE fonksiyon.
    * Seçilenlerin doğrudan (dahili) callee'leri stub olarak eklenir (en fazla MAX_STUBS).
    """
    # Kütüphane/stub kaydı ne olursa olsun puan 0: Top-N'e girip boş yere decompile
    # edilmesin, LLM token bütçesi harcamasın (propagate_priority sonrası da garanti).
    for r in records:
        if r.get("is_library"):
            r["priority"] = 0

    ranked = sorted(records, key=lambda r: (-r["priority"], r["size"], r["offset"]))
    chosen = []
    seen = set()

    def add(r):
        if r["offset"] not in seen and len(chosen) < MAX_DECOMPILE:
            chosen.append(r)
            seen.add(r["offset"])

    # Entry point / main is always analyzed; compiler stubs must not crowd it out.
    for r in records:
        if r.get("is_entry") or is_entry_name(r.get("name")):
            add(r)

    scored = [r for r in ranked if r["priority"] > 0]
    if scored:
        for r in scored:
            add(r)
    else:
        pool = [r for r in records if not r["is_library"] and 0 < r["size"] <= LARGE_FUNCTION_BYTES]
        pool.sort(key=lambda r: (-r["size"], r["offset"]))
        for r in pool[:FALLBACK_DECOMPILE]:
            add(r)

    by_offset = {r["offset"]: r for r in records}
    seen = set(r["offset"] for r in chosen)
    stubs = []
    for record in chosen:
        for callee in record["callees"]:
            if callee in seen:
                continue
            target = by_offset.get(callee)
            if target is None:  # harici (import) fonksiyon
                continue
            seen.add(callee)
            stubs.append(target)
            if len(stubs) >= MAX_STUBS:
                return chosen, stubs
    return chosen, stubs


def write_results(path, results):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, ensure_ascii=True)


def read_input(path):
    """(hints, findings, combo_apis, decoded_hints) döndürür; hata: boş değerler."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        printerr("[export_functions] girdi okunamadi: " + str(exc))  # noqa: F821 (Ghidra)
        return [], [], {}, []
    if not isinstance(data, dict):
        return [], [], {}, []

    hints = data.get("hints")
    findings = data.get("findings")
    combo_apis = data.get("combo_apis")
    decoded_hints = data.get("decoded_hints")
    return (
        hints if isinstance(hints, list) else [],
        findings if isinstance(findings, list) else [],
        combo_apis if isinstance(combo_apis, dict) else {},
        decoded_hints if isinstance(decoded_hints, list) else [],
    )


# --------------------------------------------------------------------------- #
# Ghidra API'sine bağlı kısım
# --------------------------------------------------------------------------- #
def fmt_addr(addr):
    """Ghidra adresini '0x401000' biçimine çevirir (hint formatıyla tutarlı)."""
    return "0x%x" % (int(addr.getOffset()) & 0xFFFFFFFFFFFFFFFF)


def map_hints_to_functions(hints):
    """Hint adreslerini içeren fonksiyonları bulur: {entry_str: [rule, ...]}."""
    hits = {}
    for hint in hints:
        try:
            addr = toAddr(int(str(hint["offset"]), 16))  # noqa: F821 (Ghidra)
            func = getFunctionContaining(addr)  # noqa: F821 (Ghidra)
            if func is None:
                continue
            entry = fmt_addr(func.getEntryPoint())
            rule = str(hint.get("rule", ""))
            rules = hits.setdefault(entry, [])
            if rule and rule not in rules:
                rules.append(rule)
        except Exception as exc:
            printerr("[export_functions] hint islenemedi: " + str(exc))  # noqa: F821
    return hits


def _iter_defined_data():
    """Defined strings/data: DefinedDataIterator if available, else Listing.getDefinedData.

    Ghidra 12.1.4 does not expose ``DefinedDataIterator.definedStrings``; the
    Listing fallback is the real path. The iterator branch keeps the fake-Ghidra
    unit tests and older versions working.
    """
    try:
        from ghidra.program.util import DefinedDataIterator

        if hasattr(DefinedDataIterator, "definedStrings"):
            yield from DefinedDataIterator.definedStrings(currentProgram)  # noqa: F821
            return
    except Exception:
        pass
    listing = currentProgram.getListing()  # noqa: F821
    for i, data in enumerate(listing.getDefinedData(True)):  # noqa: F821
        if i >= MAX_DEFINED_DATA:
            break
        yield data


def _function_for_ref(ref, ref_manager, func_manager, depth=0):
    """Resolve a reference to a containing function; follow data pointer chains."""
    try:
        source = ref.getFromAddress()
    except Exception:
        return None
    if source is None or not source.isMemoryAddress():
        return None
    func = func_manager.getFunctionContaining(source)
    if func is not None:
        return func
    if depth >= 3:
        return None
    try:
        for ref2 in ref_manager.getReferencesTo(source):
            func = _function_for_ref(ref2, ref_manager, func_manager, depth + 1)
            if func is not None:
                return func
    except Exception:
        return None
    return None


def map_iocs_to_functions(target_iocs):
    """Programın tanımlı string'lerinde IoC arar; referans veren fonksiyonlara eşler.

    Dönüş: {fonksiyon_giriş_adresi: [ioc, ...]}. String'e gelen referansın kaynak
    adresini içeren fonksiyon bulunur; doğrudan kod referansı yoksa veri/pointer
    zinciri 3 hop'a kadar izlenir (global ``const char *u`` durumu). Hata olursa
    o ana kadar bulunanlar döner.
    """
    hits = {}
    if not target_iocs:
        return hits
    seen = matched_data = refs_seen = 0
    try:
        ioc_index = build_ioc_index(target_iocs)
        ref_manager = currentProgram.getReferenceManager()  # noqa: F821 (Ghidra)
        func_manager = currentProgram.getFunctionManager()  # noqa: F821 (Ghidra)
        for data in _iter_defined_data():
            seen += 1
            try:
                value = data.getValue()
                text = str(value) if value is not None else str(data.getDefaultValueRepresentation())
                matched = match_iocs(text, ioc_index)
                if not matched:
                    continue
                matched_data += 1
                # The IoC may start at an offset inside the defined string (Ghidra
                # sometimes keeps a leading length/format byte, e.g. "?http://...").
                addrs = [data.getAddress()]
                low = str(text).lower()
                for ioc in matched:
                    pos = low.find(str(ioc).lower())
                    if pos > 0:
                        try:
                            addrs.append(data.getAddress().add(pos))
                        except Exception:
                            pass
                for addr in addrs:
                    for ref in ref_manager.getReferencesTo(addr):
                        refs_seen += 1
                        func = _function_for_ref(ref, ref_manager, func_manager)
                        if func is None:
                            continue
                        add_ioc_hits(hits, fmt_addr(func.getEntryPoint()), matched)
            except Exception as exc:
                printerr("[export_functions] string islenemedi: " + str(exc))  # noqa: F821
    except Exception as exc:
        printerr("[export_functions] IoC eslemesi basarisiz: " + str(exc))  # noqa: F821
    if os.environ.get("CROWBAR_IOC_DEBUG"):
        printerr(f"[export_functions] ioc debug: seen={seen} matched_data={matched_data} "
                 f"refs={refs_seen} hits={len(hits)}")  # noqa: F821
    return hits


FLOSS_PIE_BASE = 0x2000000  # FLOSS/PyVivisect emulation base for PIE samples


def _ghidra_candidates(raw):
    """Address candidates: raw, and (for PIE) FLOSS base 0x2000000 -> Ghidra image base."""
    if raw is None:
        return []
    try:
        n = int(raw, 16) if isinstance(raw, str) and raw.lower().startswith("0x") else int(raw)
    except Exception:
        return []
    out = []
    try:
        a = toAddr(n)  # noqa: F821
        if a is not None:
            out.append(a)
    except Exception:
        pass
    if n >= FLOSS_PIE_BASE:
        try:
            base = currentProgram.getImageBase().getOffset()  # noqa: F821
            a = toAddr(n - FLOSS_PIE_BASE + base)  # noqa: F821
            if a is not None:
                out.append(a)
        except Exception:
            pass
    return out


def map_decoded_hints_to_functions(decoded_hints):
    """FLOSS decoded/tight/stack metadata'sını fonksiyonlara bağlar.

    ``function`` / ``decoded_at`` / ``program_counter`` adreslerini içeren
    fonksiyonu bulur; decoder helper ise doğrudan çağıranları da (1 hop) ekler.
    ``address`` verilmişse string referanslarını da izler.
    """
    hits = {}
    if not decoded_hints:
        return hits
    try:
        from ghidra.util.task import TaskMonitor  # noqa: F401

        ref_manager = currentProgram.getReferenceManager()  # noqa: F821
        func_manager = currentProgram.getFunctionManager()  # noqa: F821
        for hint in decoded_hints:
            if not isinstance(hint, dict):
                continue
            value = str(hint.get("value", "")).strip()
            if not value:
                continue
            funcs = []
            for key in ("function", "decoded_at", "program_counter"):
                for addr in _ghidra_candidates(hint.get(key)):
                    func = func_manager.getFunctionContaining(addr)
                    if func is not None:
                        funcs.append(func)
            for addr in _ghidra_candidates(hint.get("address")):
                for ref in ref_manager.getReferencesTo(addr):
                    f = _function_for_ref(ref, ref_manager, func_manager)
                    if f is not None:
                        funcs.append(f)
            for func in list(funcs):
                try:
                    for caller in func.getCallingFunctions(TaskMonitor.DUMMY):
                        funcs.append(caller)
                except Exception:
                    pass
            for func in funcs:
                add_ioc_hits(hits, fmt_addr(func.getEntryPoint()), [value])
    except Exception as exc:
        printerr("[export_functions] decoded hint eslemesi basarisiz: " + str(exc))  # noqa: F821
    return hits


def get_callees(func):
    """Çağrılan fonksiyonlar: (hex adresler, isimler). JSON'a sadece adresler yazılır."""
    from ghidra.util.task import TaskMonitor

    addrs = []
    names = []
    try:
        for callee in func.getCalledFunctions(TaskMonitor.DUMMY):
            addr = fmt_addr(callee.getEntryPoint())
            if addr in addrs:
                continue
            addrs.append(addr)
            names.append(str(callee.getName()))
            if len(addrs) >= MAX_CALLEES:
                break
    except Exception as exc:
        printerr("[export_functions] callees alinamadi: " + str(exc))  # noqa: F821
    return addrs, names


def get_xrefs(func):
    """Fonksiyona gelen referansların kaynak adresleri ('0x...'; tekil, en fazla MAX_XREFS)."""
    xrefs = []
    try:
        ref_manager = currentProgram.getReferenceManager()  # noqa: F821 (Ghidra)
        for ref in ref_manager.getReferencesTo(func.getEntryPoint()):
            source = ref.getFromAddress()
            if not source.isMemoryAddress():
                continue
            text = fmt_addr(source)
            if text not in xrefs:
                xrefs.append(text)
            if len(xrefs) >= MAX_XREFS:
                break
    except Exception as exc:
        printerr("[export_functions] xrefs alinamadi: " + str(exc))  # noqa: F821
    return xrefs


def decompile(decomp, func):
    """(c_code, warnings) döndürür. Decompiler hata mesajı boş değilse uyarıya eklenir."""
    warnings = []
    try:
        res = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor)  # noqa: F821
    except Exception as exc:
        return "", ["decompile exception: " + str(exc)]
    if res is None:
        return "", ["decompiler sonuc dondurmedi"]

    message = res.getErrorMessage()
    if message is not None and str(message).strip():
        warnings.append(str(message).strip())
    if res.isTimedOut():
        warnings.append("decompile timeout")

    if not res.decompileCompleted():
        return "", warnings or ["decompile tamamlanamadi"]
    decompiled = res.getDecompiledFunction()
    code = str(decompiled.getC()) if decompiled is not None else ""
    return code, warnings


def collect_records(hits, combo_apis, ioc_hits=None):
    """TÜM fonksiyonlar için decompile'sız kayıt (ad, adres, size, callees, priority) üretir.

    ``ioc_hits``: {giriş_adresi: [ioc, ...]} (``map_iocs_to_functions`` çıktısı).
    """
    ioc_hits = ioc_hits or {}
    records = []
    try:
        entry_point = currentProgram.getEntryPoint()  # noqa: F821 (Ghidra)
    except Exception:
        entry_point = None
    for func in currentProgram.getFunctionManager().getFunctions(True):  # noqa: F821 (Ghidra)
        try:
            if func.isExternal():
                continue

            entry = fmt_addr(func.getEntryPoint())
            capa_hits = list(hits.get(entry, []))
            iocs = list(ioc_hits.get(entry, []))
            size = int(func.getBody().getNumAddresses())
            callee_addrs, callee_names = get_callees(func)
            try:
                is_entry = bool(entry_point is not None and func.getEntryPoint() == entry_point)
            except Exception:
                is_entry = False

            reason = library_reason(func, size)
            is_library = bool(reason)
            # Kanıt/entry istisnası: ad/boyut sezgisi tek başına kanıt taşıyan veya entry/main
            # fonksiyonu kütüphane yapmaz (Ghidra thunk/external bayrağı yine kesindir).
            if reason in SOFT_LIBRARY_REASONS and (
                    is_entry or is_entry_name(func.getName()) or capa_hits or iocs):
                is_library = False

            records.append({
                "offset": entry,
                "name": str(func.getName()),
                "priority": compute_priority(capa_hits, callee_names, size, is_library, combo_apis, iocs),
                "size": size,
                "is_library": is_library,
                "callees": callee_addrs,
                "xrefs": [],
                "decompile_warnings": [],
                "capa_hits": capa_hits,
                "iocs": iocs,
                "is_entry": is_entry,
                "c_code": "",
                "llm_summary": "",
                "_func": func,
            })
        except Exception as exc:
            printerr("[export_functions] fonksiyon puanlanamadi: " + str(exc))  # noqa: F821
    return records


def main():
    from ghidra.app.decompiler import DecompInterface

    args = getScriptArgs()  # noqa: F821 (Ghidra)
    if len(args) < 2:
        printerr("Kullanim: export_functions.py <ghidra_input_json_path> <out_json_path>")  # noqa: F821
        return
    input_json_path, out_json_path = args[0], args[1]

    results = []
    try:
        hints, findings, combo_apis, decoded_hints = read_input(input_json_path)
        hits = map_hints_to_functions(hints)
        combo_set = active_combo_apis(findings, combo_apis)

        ioc_hits = map_iocs_to_functions(collect_target_iocs(findings))
        decoded_hits = map_decoded_hints_to_functions(decoded_hints)
        for entry, values in decoded_hits.items():
            add_ioc_hits(ioc_hits, entry, values)
        println("[export_functions] %d fonksiyon IoC/decoded string'ine referans veriyor" % len(ioc_hits))  # noqa: F821

        records = collect_records(hits, combo_set, ioc_hits)
        propagate_priority(records)
        chosen, stubs = plan_export(records)
        println("[export_functions] %d fonksiyon tarandi (%d kutuphane/stub), %d decompile edilecek, %d stub" % (  # noqa: F821
            len(records), sum(1 for r in records if r["is_library"]), len(chosen), len(stubs)))

        decomp = DecompInterface()
        decomp.openProgram(currentProgram)  # noqa: F821
        try:
            for record in chosen:
                record["c_code"], record["decompile_warnings"] = decompile(decomp, record["_func"])
        finally:
            decomp.dispose()

        for record in chosen + stubs:
            record["xrefs"] = get_xrefs(record["_func"])
            del record["_func"]
            record.pop("is_entry", None)
            results.append(record)
    except Exception as exc:
        printerr("[export_functions] beklenmeyen hata: " + str(exc))  # noqa: F821

    # Hata olsa bile (boş da olsa) çıktı dosyasını her zaman yaz
    write_results(out_json_path, results)
    println("[export_functions] %d kayit yazildi: %s" % (len(results), out_json_path))  # noqa: F821


try:
    currentProgram  # noqa: B018, F821 (Ghidra tarafından enjekte edilir)
except NameError:
    pass  # Ghidra dışında import edildi (testler): main() çalıştırma
else:
    main()
