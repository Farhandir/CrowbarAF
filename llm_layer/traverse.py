"""Bottom-up gezinme: call graph -> SCC'ler -> callee-once sira.

Donguler (recursion) icin SCC'ler sozlesir; her SCC tek birim gibi islenir.
"""
from __future__ import annotations

from collections import deque

from .types import FunctionInfo


def build_graph(functions: list[FunctionInfo]) -> dict[str, list[str]]:
    known = {f.offset for f in functions}
    return {f.offset: [c for c in f.callees if c in known] for f in functions}


def scc_order(functions: list[FunctionInfo]) -> list[list[str]]:
    """SCC'leri **callee-once** (bottom-up) sirada dondurur.

    Ayni SCC icindeki fonksiyonlar birlikte islenmeli (dongu).
    """
    adj = build_graph(functions)
    nodes = list(adj.keys())
    if not nodes:
        return []

    # 1) bitis sirasi (iteratif DFS)
    visited: set[str] = set()
    order: list[str] = []
    for s in nodes:
        if s in visited:
            continue
        visited.add(s)
        stack = [(s, 0)]
        while stack:
            v, i = stack[-1]
            if i < len(adj[v]):
                w = adj[v][i]
                stack[-1] = (v, i + 1)
                if w not in visited:
                    visited.add(w)
                    stack.append((w, 0))
            else:
                order.append(v)
                stack.pop()

    # 2) ters grafik
    radj: dict[str, list[str]] = {n: [] for n in nodes}
    for v in nodes:
        for w in adj[v]:
            radj[w].append(v)

    # 3) Ters bitis sirasina gore SCC'ler (Kosaraju)
    comp: dict[str, int] = {}
    comps: list[list[str]] = []
    for s in reversed(order):
        if s in comp:
            continue
        cid = len(comps)
        members: list[str] = []
        stack = [s]
        comp[s] = cid
        while stack:
            v = stack.pop()
            members.append(v)
            for w in radj[v]:
                if w not in comp:
                    comp[w] = cid
                    stack.append(w)
        comps.append(members)

    # 4) condensation DAG: caller -> callee
    dag: dict[int, set[int]] = {i: set() for i in range(len(comps))}
    indeg = [0] * len(comps)
    for v in nodes:
        for w in adj[v]:
            a, b = comp[v], comp[w]
            if a != b and b not in dag[a]:
                dag[a].add(b)
                indeg[b] += 1

    # 5) caller-once topolojik sira, sonra ters cevir -> callee-once
    q = deque([i for i in range(len(comps)) if indeg[i] == 0])
    topo: list[int] = []
    while q:
        i = q.popleft()
        topo.append(i)
        for j in dag[i]:
            indeg[j] -= 1
            if indeg[j] == 0:
                q.append(j)

    if len(topo) < len(comps):  # beklenmez (SCC DAG dongusuzdur) - guvenlik
        topo += [i for i in range(len(comps)) if i not in set(topo)]

    return [comps[i] for i in reversed(topo)]
