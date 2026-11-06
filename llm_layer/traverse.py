"""Bottom-up traversal: call graph -> SCCs -> callee-first levels.

`scc_levels`: SCCs at the same level are independent of each other (can be processed in parallel).
For cycles (recursion) SCCs are contracted; each SCC is processed as a single unit.
"""
from __future__ import annotations

from collections import deque

from .types import FunctionInfo


def build_graph(functions: list[FunctionInfo]) -> dict[str, list[str]]:
    known = {f.offset for f in functions}
    return {f.offset: [c for c in f.callees if c in known] for f in functions}


def _kosaraju(adj: dict[str, list[str]]) -> tuple[list[list[str]], dict[str, int]]:
    nodes = list(adj.keys())
    if not nodes:
        return [], {}

    # 1) finish order (iterative DFS)
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

    # 2) reverse graph
    radj: dict[str, list[str]] = {n: [] for n in nodes}
    for v in nodes:
        for w in adj[v]:
            radj[w].append(v)

    # 3) SCCs
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
    return comps, comp


def _condensation(adj: dict[str, list[str]], comp: dict[str, int], n: int) -> tuple[dict[int, set[int]], dict[int, set[int]]]:
    """(caller->callee, callee->caller) condensation DAG."""
    dag: dict[int, set[int]] = {i: set() for i in range(n)}
    rev: dict[int, set[int]] = {i: set() for i in range(n)}
    for v, callees in adj.items():
        for w in callees:
            a, b = comp[v], comp[w]
            if a != b and b not in dag[a]:
                dag[a].add(b)
                rev[b].add(a)
    return dag, rev


def scc_levels(functions: list[FunctionInfo]) -> list[list[list[str]]]:
    """Return the SCCs **level by level** (level 0 = leaves).

    SCCs at the same level have no dependencies between them -> can be processed in parallel.
    """
    adj = build_graph(functions)
    comps, comp = _kosaraju(adj)
    if not comps:
        return []
    n = len(comps)
    dag, rev = _condensation(adj, comp, n)

    # bottom-up: those with outdeg (callee count) 0 are level 0
    remaining = {i: len(dag[i]) for i in range(n)}
    depth: dict[int, int] = {}
    q = deque([i for i in range(n) if remaining[i] == 0])
    for i in q:
        depth[i] = 0
    while q:
        leaf = q.popleft()
        for caller in rev[leaf]:
            depth[caller] = max(depth.get(caller, -1), depth[leaf] + 1)
            remaining[caller] -= 1
            if remaining[caller] == 0:
                q.append(caller)

    levels: dict[int, list[list[str]]] = {}
    for i, members in enumerate(comps):
        levels.setdefault(depth.get(i, 0), []).append(members)
    return [levels[d] for d in sorted(levels)]


def scc_order(functions: list[FunctionInfo]) -> list[list[str]]:
    """Return the SCCs in flat **callee-first** order (flattened levels)."""
    return [scc for level in scc_levels(functions) for scc in level]
