"""Crowbar - Otonom Statik Zararlı Yazılım Analiz Sistemi (giriş noktası).

Kullanım:
    python main.py <analiz_edilecek_dosya>
    python main.py --diagram        # Mermaid grafik çıktısı
"""

from __future__ import annotations

import argparse
import logging
import sys

from graph import build_graph
from state import AgentState


def main() -> None:
    # Windows konsolu varsayılan olarak cp1252 kullanır; Türkçe karakterler için UTF-8 zorla.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Crowbar statik analiz hattı")
    parser.add_argument("file_path", nargs="?", help="Analiz edilecek dosya")
    parser.add_argument("--diagram", action="store_true", help="Graph'i Mermaid olarak yazdır")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    app = build_graph()

    if args.diagram:
        print(app.get_graph().draw_mermaid())
        return
    if not args.file_path:
        parser.error("file_path gerekli")

    result = app.invoke(AgentState(file_path=args.file_path))
    print(AgentState(**result).model_dump_json(indent=2))


if __name__ == "__main__":
    main()
