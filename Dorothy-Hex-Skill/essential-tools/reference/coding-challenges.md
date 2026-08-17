# Competitive Coding Challenge Quickstart

CTF "Coding" challenges are competitive-programming style: the service streams test cases, you solve in seconds, score above a threshold to earn the flag. Recurring patterns and gotchas:

## Connection & I/O
- Spawn docker → `nc host port` connects to a stdin/stdout judge. Use `pwntools.remote` for binary-safe I/O.
- Judges almost always send a problem statement (1–3 lines), then the test input, then expect your answer, then loop.
- **Output format gotcha**: problem may say "N-1 lines" but grader actually wants a single space-separated line, OR vice versa. Always try BOTH formats before giving up — they consume separate submission attempts on the judge but are cheap to test (no flag-submission cost).

## Workflow
1. Connect, read prompt fully, save raw exchange to logs/.
2. Identify problem class:
   - Graph (shortest path, MST, max-flow, tree DP, LCA)
   - DP / sequence (LIS, edit distance, knapsack)
   - Number theory (modular arithmetic, primes, divisors, CRT)
   - String (regex, suffix array, KMP, hashing)
   - Geometry (convex hull, sweepline)
   - Math optimization (binary search the answer, ternary search)
3. Write a brute force first; stress-test against it on small inputs (N ≤ 10) to validate correctness.
4. Replace with the efficient algorithm; run stress test again.
5. Loop: read problem → solve → submit → read next → ... until judge sends the flag wrapper.

## Scaling rules of thumb
- N ≤ 25: bitmask DP, brute force, meet-in-the-middle.
- N ≤ 5000: O(N²) is fine.
- N ≤ 200_000: need O(N log N).
- N ≤ 500_000–10⁶: O(N) or O(N log N) with low constant. Iterative DFS, no recursion (Python recursion limit is 1000 by default; even with `sys.setrecursionlimit` deep chains overflow C stack).

## Common advanced toolkit
- **Convex Hull Trick (CHT)** — when DP has form `f(u) = a + min_v(b·m_v + c_v)`. If slopes are monotonic along the query order, use Li Chao or push/pop hull stack.
- **Tree DP with CHT on DFS path** — when slopes are monotonic along ancestor chains; push hull on DFS enter, pop on DFS exit. Each node has O(log N) work via binary-search the hull.
- **Heavy–Light Decomposition** — path queries on trees in O(log² N).
- **Mo's algorithm** — offline range queries in O((N+Q)·√N).
- **2-SAT** — implication graphs, Tarjan SCC.

## Worked example — large-tree min-cost ancestor jump

When you encounter a tree of up to 500k nodes asking for min cost ancestor-jump per non-root and the recurrence factors into a min over lines parametrised by `transfer[u]` and `-D[a]`: use iterative DFS + push/pop CHT (O(N log N), ~1.7s on a 500k chain). Output format gotcha to watch for: problem text may say "N-1 lines" while the grader accepts space-separated on a single line — try both.

## Anti-patterns
- Don't waste submission attempts on output-format guesses for the *flag*; only the judge feedback for the answer phase is free.
- Don't use Python recursion for tree problems with N > 50,000 — you'll get RecursionError or C stack overflow.
- Don't trust example output format wording over the example itself: when they conflict, mimic the example structure exactly.
