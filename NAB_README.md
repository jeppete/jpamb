# NAB – Integration of Abstractions

## Overview

NAB (Novel Abstract integration) integrates dynamic execution traces from IIN with abstract domains from IAB to produce refined initial abstract states for static analysis.

This module implements the core innovation of our DTU 02242 project: **dynamic refinement heuristics** that use observed concrete execution values to set initial abstract states, enabling more precise static analysis.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     NAB Integration Layer                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   IIN (Interpreter)              IAB (Abstractions)             │
│   ─────────────────              ──────────────────             │
│   • Executes bytecode            • SignDomain                   │
│   • Produces traces/             • IntervalDomain               │
│   • Records samples              • DomainRefinement             │
│                                                                  │
│              ↓                           ↓                       │
│        traces/*.json           refine_from_trace()              │
│              ↓                           ↓                       │
│   ┌──────────────────────────────────────────────────┐          │
│   │        integrate_abstractions(trace_path)         │          │
│   │                                                   │          │
│   │   1. Read IIN JSON trace                         │          │
│   │   2. Extract concrete samples                     │          │
│   │   3. Apply IAB refinement                        │          │
│   │   4. Return AbstractValue per local               │          │
│   └──────────────────────────────────────────────────┘          │
│                         ↓                                        │
│              Dict[int, AbstractValue]                            │
│              (sign + interval per local)                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Proposal Reference

From our approved proposal (20 October 2025), page 2:

> "dynamic traces to set initial abstracts like x>0"

This dynamic refinement heuristic, combined with classic sign/interval domains, is our approved novelty contribution in 02242.

## Key Components

### 1. IIN Integration (Interpreter)

IIN (`solutions/interpreter.py`) produces JSON trace files in `traces/` directory:

```json
{
  "method": "jpamb.cases.Simple.assertPositive:(I)V",
  "coverage": {
    "executed_pcs": [0, 1, 2, 3, 8],
    "uncovered_pcs": [4, 5, 6, 7],
    "branches": {"1": [false], "3": [true]}
  },
  "values": {
    "local_0": {
      "samples": [1, 1, 1, 1, 1],
      "always_positive": true,
      "never_negative": true,
      "never_zero": true,
      "sign": "positive",
      "interval": [1, null]
    }
  }
}
```

### 2. IAB Integration (Abstractions)

IAB (`solutions/abstractions.py`) provides:

- **SignDomain**: POSITIVE, NEGATIVE, ZERO, NON_ZERO, NON_NEGATIVE, NON_POSITIVE, TOP, BOTTOM
- **IntervalDomain**: [low, high] bounds
- **DomainRefinement.from_concrete_values()**: Refines domains from samples

### 3. NAB Module

NAB (`solutions/nab_integration.py`) provides:

- **`integrate_abstractions(trace_path)`**: Main integration function
- **`AbstractValue`**: Combined sign + interval for each local
- **`IntegrationResult`**: Full result with metadata

## Usage

### Basic Usage

```python
from solutions.nab_integration import integrate_abstractions

# Integrate trace to get refined abstract state
result = integrate_abstractions("traces/jpamb.cases.Simple_assertPositive_IV.json")

# Access refined domains for local_0
print(result[0].sign)      # SignDomain(SignValue.POSITIVE)
print(result[0].interval)  # IntervalDomain([1, 1])
```

### Proposal Example

From proposal §1.3.1: `process(int x)` with samples `[5, 10, 15, 20, 25]`:

```python
from solutions.nab_integration import process_example

result = process_example()

# local_1 should be refined to:
# - sign = POSITIVE (all samples > 0)
# - interval = [5, 25]
print(result[1].sign.value)  # SignValue.POSITIVE
print(result[1].interval)    # [5, 25]
```

### Batch Processing

```python
from solutions.nab_integration import integrate_all_traces

# Process all traces in directory
all_results = integrate_all_traces("traces")

for method_name, result in all_results.items():
    print(f"{method_name}:")
    for idx, abstract_val in result.abstract_values.items():
        print(f"  local_{idx}: sign={abstract_val.sign}, interval={abstract_val.interval}")
```

## Sign Domain Refinement Rules

| Observed Samples | Refined Sign |
|------------------|--------------|
| All positive | POSITIVE |
| All negative | NEGATIVE |
| All zero | ZERO |
| Positive + negative | NON_ZERO |
| Positive + zero | NON_NEGATIVE |
| Negative + zero | NON_POSITIVE |
| All three | TOP |
| Empty | BOTTOM |

## Interval Domain Refinement Rules

- **Interval bounds**: `[min(samples), max(samples)]`
- **Single sample**: Point interval `[x, x]`
- **Empty samples**: BOTTOM

## Testing

Run the test suite:

```bash
pytest tests/test_nab_integration.py -v
```

Test coverage includes:
- Proposal example verification
- Sign domain refinement (all 8 cases)
- Interval domain refinement
- Trace file parsing
- Edge cases (empty samples, missing files)
- Real trace file integration

## File Structure

```
solutions/
├── interpreter.py      # IIN - produces traces/*.json
├── abstractions.py     # IAB - SignDomain, IntervalDomain
└── nab_integration.py  # NAB - this module

tests/
└── test_nab_integration.py  # NAB tests

traces/
└── *.json             # IIN output files
```

## Dependencies

NAB uses only existing project code:
- `solutions.abstractions` (IAB)
- Standard library: `json`, `pathlib`, `typing`, `dataclasses`

No new external dependencies required.

## Authors

DTU 02242 Program Analysis - Group 21

## License

See project LICENSE file.
