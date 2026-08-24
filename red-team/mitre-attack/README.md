# MITRE ATT&CK Mapping

Ties the whole framework to [MITRE ATT&CK](https://attack.mitre.org/) (Enterprise).

## Files

| File | What it is |
|------|-----------|
| `framework.json` | Per-tactic coverage map: techniques implemented, detection methods, effectiveness/false-positive estimates, and gap analysis. |
| `navigator-layer.json` | An ATT&CK **Navigator layer** — a coverage heatmap of every technique referenced across the framework. Generated; do not hand-edit. |
| `build-navigator-layer.py` | Regenerates `navigator-layer.json` by scanning `red-team/` for technique IDs. |

## View the coverage heatmap

1. Regenerate the layer (after any change to scenarios, actors, detections, recon):
   ```bash
   python3 build-navigator-layer.py
   ```
2. Open the official Navigator: <https://mitre-attack.github.io/attack-navigator/>
3. **Open Existing Layer → Upload from local →** `navigator-layer.json`

Each technique's **score** is how many times it's referenced across the
framework, so the darkest cells are the techniques most reinforced by scenarios,
actor TTPs, and detections. The per-technique tooltip (comment) shows *where*
each is used: `scenario`, `actor-TTP`, `coverage-map`, `detection`, or `recon`.

## Why it's useful

- **Spot concentration** — the heatmap shows where coverage clusters (ransomware
  impact, execution, persistence) and where it's thin.
- **Find gaps** — techniques absent from the layer are candidates for the next
  scenario or detection.
- **Communicate scope** — one picture, on the tool defenders already use, that
  says exactly what this framework exercises.

Current snapshot: ~101 unique techniques (~51 sub-techniques). All IDs follow the
Enterprise ATT&CK `TNNNN[.NNN]` scheme; the authoritative reference for each is
`https://attack.mitre.org/techniques/<ID>/`.
