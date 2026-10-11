# First-installation operator prompts — fixture evidence

Captured on 2026-09-11 in a real Electron window using simulated device state and a mock continuation delegate. No native device access, firmware transfer, reset, or power cycle was performed.

The four screenshots show the first and second requested USB power cycles, each with the selected dock present and temporarily absent. Both prompts preserve the operation lock, name the same USB port, leave J7 open, and offer a separate **Continue after reconnecting** button. The first prompt follows staging; the second follows bootstrap programming.

`inspection.json` records the DOM bounds and continuation checks: no horizontal overflow, no automatic continuation, exactly one mock request after an operator click, button disabled after acceptance, and no premature success banner. Each captured image was visually inspected for complete readable prompts and buttons.

To reproduce from the repository root:

```sh
env -u ELECTRON_RUN_AS_NODE ./node_modules/.bin/electron docs/evidence/firmware-first-installation-20260911/verify.mjs
```

The harness uses the real renderer with `contextIsolation`, `sandbox`, and disabled Node integration. Its generated fixture page and profile are under `/tmp/openrdxmanager-installation-evidence`; all delegates remain local mocks.
