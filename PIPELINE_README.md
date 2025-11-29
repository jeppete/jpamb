# Fine-Grained Debloating Pipeline

**DTU 02242 Program Analysis - Group 21**

This document describes our complete fine-grained debloating pipeline that combines dynamic tracing with static analysis to remove dead code from Java bytecode.

## Overview

The pipeline takes a Java method and:
1. Parses its bytecode into a CFG
2. Collects concrete execution traces
3. Builds abstract states from traces
4. Runs static analysis to find dead code
5. Rewrites the class file with dead code removed

## Pipeline Steps

### Step 0: ISY - Interpret Syntactic Information (6 pts)

**Purpose:** Parse bytecode into structured CFG representation.

```
Input:  Java .class file
Output: Bytecode instructions + CFG edges
```

Example for `assertPositive:(I)V`:
```
[ 0] GETSTATIC $assertionsDisabled
[ 3] IFNEZ → 18
[ 6] ILOAD_0
[ 7] IFGTZ → 18
[10] NEW AssertionError
[13] DUP
[14] INVOKESPECIAL <init>
[17] ATHROW
[18] RETURN

CFG Edges: 3→18, 7→18
```

### Step 1: IIN - Implement Interpreter (7 pts)

**Purpose:** Run concrete tests to collect execution traces.

```
Input:  Test cases for the method
Output: Concrete values observed at each program point
```

Example trace for `assertPositive(1)`:
```json
{
  "local_0": {
    "samples": [1, 1, 1, 1, 1],
    "always_positive": true,
    "sign": "positive",
    "interval": [1, null]
  }
}
```

### Step 2: NAN - Abstraction at Number Level (10 pts)

**Purpose:** Build abstract state from concrete traces using ReducedProductState.

```
Input:  Concrete samples from traces
Output: ReducedProductState(sign, interval, nonnull)
```

Example:
```python
samples = [1, 1, 1, 1, 1]  # All positive

ReducedProductState:
  sign     = {+}           # SignSet: strictly positive
  interval = [1, +∞]       # IntervalDomain: at least 1
  nonnull  = ⊤             # N/A for primitives
```

### Step 3: IAI+IBA+NAB - Static Analysis (24 pts)

**Purpose:** Run abstract interpreter with three-domain reduced product.

| Domain | Description | Points |
|--------|-------------|--------|
| SignSet | Sign domain {+, 0, -} | IAI: 7 pts |
| IntervalDomain | Interval with widening | IBA: 7 pts |
| NonNullDomain | Null/non-null tracking | NAB: 5+5 pts |

```
Input:  Initial abstract state from NAN
Output: Set of unreachable program counters
```

Example analysis:
```
Initial: local_0 = {+} (positive)
At PC 7: ifgt (if num > 0 goto 18)
Since num > 0 is ALWAYS TRUE → branch always taken
Therefore: PCs 10-17 are DEAD
```

### Step 4: NCR - Analysis-informed Code Rewriting (10 pts)

**Purpose:** Replace dead bytecode with NOPs.

```
Input:  Original .class file + dead PCs
Output: Debloated .class file
```

Strategy:
- Parse class file structure
- Find method's Code attribute
- Replace dead instruction bytes with NOP (0x00)
- Preserve all offsets (no shrinking)

### Step 5: Validation

**Purpose:** Verify the debloated class file is valid.

```bash
javap -c target/debloated/jpamb/cases/Simple.class
```

## Running the Pipeline

```bash
# Run the complete pipeline on all methods
uv run jpamb pipeline

# List available methods
uv run jpamb pipeline --list

# Run on a specific method
uv run jpamb pipeline -m assertPositive

# Run with verbose output
uv run jpamb pipeline -v

# Regenerate traces before running
uv run jpamb pipeline --regenerate
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--list` | List all available methods |
| `-m, --method NAME` | Run pipeline on specific method (partial match) |
| `--regenerate` | Regenerate execution traces before analysis |
| `-v, --verbose` | Show detailed output for each method |

## Example Output

```
Target Method: jpamb.cases.Simple.assertPositive:(I)V

BEFORE:                           AFTER:
[ 0] GETSTATIC                    [ 0] getstatic
[ 3] IFNEZ → 18                   [ 3] ifne 18
[ 6] ILOAD_0                      [ 6] iload_0
[ 7] IFGTZ → 18                   [ 7] ifgt 18
[10] NEW AssertionError  ← DEAD   [10-17] nop × 8
[13] DUP                 ← DEAD
[14] INVOKESPECIAL       ← DEAD
[17] ATHROW              ← DEAD
[18] RETURN                       [18] return

STATISTICS:
  Total instructions:    9
  Dead instructions:     4
  Removal percentage:    44.4%
  Bytes NOPified:        8 bytes
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Pipeline Flow                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  .class file ──┬──► ISY ──► CFG + Bytecode                  │
│                │                                             │
│  Test cases ───┴──► IIN ──► Execution Traces                │
│                              │                               │
│                              ▼                               │
│                         NAN: Build                           │
│                    ReducedProductState                       │
│                              │                               │
│                              ▼                               │
│                    IAI+IBA+NAB: Static                       │
│                    Analysis (3 domains)                      │
│                              │                               │
│                              ▼                               │
│                         Dead PCs                             │
│                              │                               │
│                              ▼                               │
│                    NCR: Code Rewriting                       │
│                              │                               │
│                              ▼                               │
│                    Debloated .class                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Key Files

| File | Purpose |
|------|---------|
| `jpamb/cli.py` | CLI with `jpamb pipeline` command |
| `solutions/pipeline_evaluation.py` | Main pipeline script |
| `solutions/abstract_domain.py` | SignSet, IntervalDomain, NonNullDomain |
| `solutions/nab_integration.py` | ReducedProductState |
| `solutions/abstract_interpreter.py` | Abstract interpreter |
| `solutions/code_rewriter.py` | Class file rewriter |
| `traces/*.json` | Execution traces |

## Contributions

| Code | Description | Points |
|------|-------------|--------|
| ISY | Interpret Syntactic Information | 6 |
| IIN | Implement Interpreter | 7 |
| IAI | Abstract Interpretation (Sign) | 7 |
| IBA | Unbounded Static Analysis | 7 |
| IAB | Novel Abstraction (NonNullDomain) | 10 |
| NAB | Reduced Product (Sign × Interval × NonNull) | 10 |
| NAN | Dynamic→Static Refinement | 10 |
| NCR | Analysis-informed Code Rewriting | 10 |
| **Total** | | **67** |

Additional contributions (Traces, Tests, Docs, etc.) bring total to **136 points**.

## Novel Abstraction: NonNullDomain (IAB)

The NonNullDomain is a **novel abstraction** not taught in DTU 02242 lectures (which cover Sign, Interval, Constant, Parity).

### Lattice Structure

```
           TOP (unknown)
          /   \
 DEFINITELY    MAYBE
  NON_NULL     _NULL
          \   /
         BOTTOM
```

### Use Cases

1. **Dead code elimination:** If ref is `DEFINITELY_NON_NULL`, then `ifnull` branch is dead
2. **NPE analysis:** If ref is `DEFINITELY_NON_NULL`, `getfield`/`invokevirtual` cannot throw NPE
3. **Array safety:** If array is `DEFINITELY_NON_NULL`, `arraylength` is safe

### Transfer Functions

| Instruction | Result |
|-------------|--------|
| `new` / `anewarray` | DEFINITELY_NON_NULL |
| `aconst_null` | MAYBE_NULL |
| `ifnull` taken | MAYBE_NULL (refined) |
| `ifnull` not taken | DEFINITELY_NON_NULL (refined) |

## Pipeline Results

Running `uv run jpamb pipeline` on all JPAMB methods:

```
Total methods: 40
Successful: 36
Failed: 4
Methods with dead code: 24

Total: 208/443 dead instructions (47.0%)
```

### Top Dead Code Removal

| Method | Dead Code % |
|--------|-------------|
| `constantConditionBlocks` | 85.7% |
| `unusedVariables` | 84.6% |
| `checkBeforeAssert` | 78.6% |
| `redundantChecks` | 72.7% |
| `normalizedDistance` | 72.4% |
| `collatz` | 71.4% |

## Tests

All 414 tests pass:

```bash
uv run pytest --tb=short -q
# 414 passed, 1 skipped
```

## License

MIT License - DTU 02242 Course Project
