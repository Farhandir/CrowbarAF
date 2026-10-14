# -*- coding: utf-8 -*-
# @category CrowbarAF
#
# Ghidra analyzeHeadless -postScript betiği (Jython / Python 2.7).
# DİKKAT: Bu dosya Python 3 değil Python 2.7 sözdizimiyle yazılmalıdır
# (f-string, tip ipuçları vb. kullanma). ``currentProgram``, ``monitor``,
# ``toAddr``, ``getFunctionAt`` gibi isimler Ghidra tarafından enjekte edilir.
#
# Argümanlar (sırayla): <hints_json_path> <out_json_path>
#   hints_json_path: [{"offset": "0x401000", "rule": "encrypt data..."}, ...]
#   out_json_path:   state.DecompiledFunction şemasına uygun sözlük listesi
#
# Kullanım:
#   analyzeHeadless <dir> <proj> -import <file> \
#       -scriptPath <bu_dosyanın_dizini> \
#       -postScript export_functions.py <hints.json> <out.json>

import json

from ghidra.app.decompiler import DecompInterface

DECOMPILE_TIMEOUT_SECONDS = 60
CAPA_PRIORITY_BONUS = 5


def write_results(path, results):
    # ensure_ascii=True: Jython'da unicode/str karışıklığına karşı çıktı saf ASCII olur.
    with open(path, "w") as fh:
        fh.write(json.dumps(results, ensure_ascii=True))


def find_function(offset_str):
    """Adreste biten/başlayan fonksiyonu bulur; yoksa adresi içeren fonksiyona düşer."""
    addr = toAddr(long(offset_str, 16))
    func = getFunctionAt(addr)
    if func is None:
        # capa basic-block kapsamlı eşleşmelerde adres fonksiyonun ortasında olabilir.
        func = getFunctionContaining(addr)
    return func


def decompile(decomp, func):
    res = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor)
    if res is None or not res.decompileCompleted():
        return None
    decompiled = res.getDecompiledFunction()
    if decompiled is None:
        return None
    return decompiled.getC()


def main():
    args = getScriptArgs()
    if len(args) < 2:
        printerr("Kullanim: export_functions.py <hints_json_path> <out_json_path>")
        return
    hints_json_path, out_json_path = args[0], args[1]

    results = []
    # Tek bir fonksiyon birden fazla hint'e denk gelebilir: entry point -> kayıt
    by_entry = {}

    try:
        with open(hints_json_path, "r") as fh:
            hints = json.load(fh)
        if not isinstance(hints, list):
            hints = []

        decomp = DecompInterface()
        decomp.openProgram(currentProgram)

        for hint in hints:
            try:
                offset_str = str(hint["offset"])
                rule = hint.get("rule", "")

                func = find_function(offset_str)
                if func is None:
                    println("[export_functions] fonksiyon bulunamadi: " + offset_str)
                    continue

                entry = str(func.getEntryPoint())
                record = by_entry.get(entry)
                if record is not None:
                    # Mükerrer fonksiyon kaydı oluşturma; sadece yeni kuralı ekle
                    if rule and rule not in record["capa_hits"]:
                        record["capa_hits"].append(rule)
                    continue

                c_code = decompile(decomp, func)
                if c_code is None:
                    println("[export_functions] decompile basarisiz: " + offset_str)
                    continue

                record = {
                    "offset": offset_str,
                    "name": func.getName(),
                    "priority": CAPA_PRIORITY_BONUS,
                    "c_code": c_code,
                    "capa_hits": [rule] if rule else [],
                    "llm_summary": "",
                }
                by_entry[entry] = record
                results.append(record)
            except Exception as exc:  # tek bir hint tüm çıktıyı düşürmesin
                printerr("[export_functions] hint islenemedi: " + str(exc))

        decomp.dispose()
    except Exception as exc:
        printerr("[export_functions] beklenmeyen hata: " + str(exc))

    # Hata olsa bile (boş da olsa) çıktı dosyasını her zaman yaz
    write_results(out_json_path, results)
    println("[export_functions] %d fonksiyon yazildi: %s" % (len(results), out_json_path))


main()
