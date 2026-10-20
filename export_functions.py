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
     çok büyük fonksiyon -2, kütüphane/thunk = 0.
  3. Sadece en yüksek puanlı ilk MAX_DECOMPILE (100) fonksiyon decompile edilir.
     Puanlı fonksiyon yoksa en büyük birkaç fonksiyon (FALLBACK_DECOMPILE) denenir.
  4. Decompile edilenlerin doğrudan callee'leri ``c_code: ""`` ile (çağrı grafiği
     bağlansın diye) çıktıya eklenir; diğer yüzlerce fonksiyon çıktıya girmez.

Not: Saf mantık (puanlama/seçim) Ghidra olmadan da import edilip test edilebilir;
``main()`` yalnızca Ghidra ortamında (``currentProgram`` varsa) çalışır.
"""

import json

DECOMPILE_TIMEOUT_SECONDS = 60

CAPA_HIT_BONUS = 5
DANGEROUS_API_BONUS = 4
IMPORT_COMBO_BONUS = 4
LARGE_FUNCTION_BYTES = 10000
LARGE_FUNCTION_PENALTY = 2

MAX_DECOMPILE = 100  # Top-N: decompile edilecek en fazla fonksiyon
FALLBACK_DECOMPILE = 20  # hiç puanlı fonksiyon yoksa denenecek en büyük fonksiyon sayısı
MAX_STUBS = 500  # c_code'suz callee kayıtlarının üst sınırı
MAX_CALLEES = 50
MAX_XREFS = 50

# Küçük harfli, alt-dize eşleşmesi (CreateProcessA/W/Ex gibi varyantları da yakalar)
DANGEROUS_APIS = (
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


def compute_priority(capa_hits, callee_names, size, is_library, combo_apis):
    """Fonksiyon öncelik puanı (kütüphane/thunk her zaman 0)."""
    if is_library:
        return 0

    priority = 0
    if capa_hits:
        priority += CAPA_HIT_BONUS

    names = [base_name(n) for n in callee_names]
    if any(api in name for name in names for api in DANGEROUS_APIS):
        priority += DANGEROUS_API_BONUS
    if combo_apis and any(name in combo_apis for name in names):
        priority += IMPORT_COMBO_BONUS

    if size > LARGE_FUNCTION_BYTES:
        priority -= LARGE_FUNCTION_PENALTY
    return max(priority, 0)


def plan_export(records):
    """Kayıt listesinden (decompile edilecekler, c_code'suz callee kayıtları) seçer.

    * priority > 0 olanlar, puana göre azalan (eşitlikte küçük fonksiyon önce), ilk MAX_DECOMPILE.
    * Hiç puanlı fonksiyon yoksa: kütüphane olmayan en büyük FALLBACK_DECOMPILE fonksiyon.
    * Seçilenlerin doğrudan (dahili) callee'leri stub olarak eklenir (en fazla MAX_STUBS).
    """
    ranked = sorted(records, key=lambda r: (-r["priority"], r["size"], r["offset"]))
    chosen = [r for r in ranked if r["priority"] > 0][:MAX_DECOMPILE]

    if not chosen:
        pool = [r for r in records if not r["is_library"] and 0 < r["size"] <= LARGE_FUNCTION_BYTES]
        pool.sort(key=lambda r: (-r["size"], r["offset"]))
        chosen = pool[:FALLBACK_DECOMPILE]

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
    """(hints, findings, combo_apis) döndürür; hata durumunda boş değerler."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        printerr("[export_functions] girdi okunamadi: " + str(exc))  # noqa: F821 (Ghidra)
        return [], [], {}
    if not isinstance(data, dict):
        return [], [], {}

    hints = data.get("hints")
    findings = data.get("findings")
    combo_apis = data.get("combo_apis")
    return (
        hints if isinstance(hints, list) else [],
        findings if isinstance(findings, list) else [],
        combo_apis if isinstance(combo_apis, dict) else {},
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


def collect_records(hits, combo_apis):
    """TÜM fonksiyonlar için decompile'sız kayıt (ad, adres, size, callees, priority) üretir."""
    records = []
    for func in currentProgram.getFunctionManager().getFunctions(True):  # noqa: F821 (Ghidra)
        try:
            if func.isExternal():
                continue

            entry = fmt_addr(func.getEntryPoint())
            capa_hits = list(hits.get(entry, []))
            is_library = bool(func.isThunk())
            size = int(func.getBody().getNumAddresses())
            callee_addrs, callee_names = get_callees(func)

            records.append({
                "offset": entry,
                "name": str(func.getName()),
                "priority": compute_priority(capa_hits, callee_names, size, is_library, combo_apis),
                "size": size,
                "is_library": is_library,
                "callees": callee_addrs,
                "xrefs": [],
                "decompile_warnings": [],
                "capa_hits": capa_hits,
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
        hints, findings, combo_apis = read_input(input_json_path)
        hits = map_hints_to_functions(hints)
        combo_set = active_combo_apis(findings, combo_apis)

        records = collect_records(hits, combo_set)
        chosen, stubs = plan_export(records)
        println("[export_functions] %d fonksiyon tarandi, %d decompile edilecek, %d stub" % (  # noqa: F821
            len(records), len(chosen), len(stubs)))

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
