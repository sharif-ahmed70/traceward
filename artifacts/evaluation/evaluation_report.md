# TraceWard Evaluation Report

## A* vs. uninformed search (INTERNET -> DB01)

| algorithm | path | total_cost | hops | nodes_expanded | optimal |
|---|---|---|---|---|---|
| A* | INTERNET -> WEB01 -> APP01 -> DB01 | 8.28 | 3 | 4 | True |
| Uniform Cost Search | INTERNET -> WEB01 -> APP01 -> DB01 | 8.28 | 3 | 8 | True |
| Breadth-First Search | INTERNET -> WEB01 -> APP01 -> DB01 | 8.28 | 3 | 7 | True |

All simple attack paths (exhaustive enumeration, cheapest first):

| path | total_cost | hops |
|---|---|---|
| INTERNET -> WEB01 -> APP01 -> DB01 | 8.28 | 3 |
| INTERNET -> WEB01 -> AUTH01 -> APP01 -> DB01 | 11.13 | 4 |
| INTERNET -> VPN01 -> EMP01 -> AUTH01 -> APP01 -> DB01 | 12.15 | 5 |

## CSP search strategies

| case | tasks | strategy | status | assignments | backtracks | constraint_checks | pruned_values | constraints_satisfied |
|---|---|---|---|---|---|---|---|---|
| baseline | 10 | Plain Backtracking | feasible | 11 | 1 | 45 | 0 | True |
| baseline | 10 | Backtracking + MRV/Degree | feasible | 11 | 1 | 270 | 0 | True |
| baseline | 10 | Backtracking + Forward Checking | feasible | 11 | 1 | 93 | 40 | True |
| baseline | 10 | MRV/Degree + Forward Checking | feasible | 11 | 1 | 105 | 52 | True |
| baseline | 10 | MRV/Degree + FC + AC-3 | feasible | 10 | 0 | 587 | 46 | True |
| stress | 17 | Plain Backtracking | feasible | 6845 | 6828 | 126839 | 0 | True |
| stress | 17 | Backtracking + MRV/Degree | feasible | 18 | 1 | 1791 | 0 | True |
| stress | 17 | Backtracking + Forward Checking | feasible | 6813 | 6796 | 139362 | 19487 | True |
| stress | 17 | MRV/Degree + Forward Checking | feasible | 18 | 1 | 390 | 109 | True |
| stress | 17 | MRV/Degree + FC + AC-3 | feasible | 17 | 0 | 2265 | 99 | True |
| overload | 17 | Plain Backtracking | infeasible | 54064 | 54064 | 208816 | 0 | False |
| overload | 17 | Backtracking + MRV/Degree | infeasible | 308 | 308 | 28350 | 0 | False |
| overload | 17 | Backtracking + Forward Checking | infeasible | 49959 | 49959 | 338532 | 296425 | False |
| overload | 17 | MRV/Degree + Forward Checking | infeasible | 308 | 308 | 5690 | 1646 | False |
| overload | 17 | MRV/Degree + FC + AC-3 | infeasible | 358 | 358 | 7468 | 2120 | False |

Timing (ms) varies by machine and is recorded in csp_comparison.csv.
