# CONFIG

Target settings are supplied through YAML or JSON config files. The repository
includes an example and a synthetic sample config, not private target data.
Start from [`../branchloom/profiles/neutral.yml`](../../branchloom/profiles/neutral.yml),
copy it, and keep private target settings **out of git**. `.gitignore` is not a
content filter. The IDA pipeline and verifier integration have not been validated
end to end; see [implementation status](../IMPLEMENTATION_STATUS.md).

## Sections

- **`image`** — the on-disk binary. This is the single source of truth for *pristine*
  bytes for the restore helpers; not every pass restores it automatically.
  **`reloc_image`** (optional) — a
  relocation-applied image or live dump used only for reading pointer **tables**
  (a raw `.so`'s GOT/table entries are not relocated and must not be trusted).

- **`exec_segments`** — where to scan, **explicitly**, by `name` (e.g. `.text`) *or*
  by `[start, end)` range. The tool never assumes a segment name; some binaries name
  their code segment `LOAD` or `ROM`.

- **`cff`** — the CFF instruction-pattern parameters as data, not code:
  `loom_idx_table_scale`/`loom_tgt_table_scale`/`entry_size`, accepted `loom_state_slot_bases`, an
  optional `loom_index_reg_allowlist` (empty = accept any register — do not hard-code a
  register-allocation guess), the OLLVM `scrambler` constants (`null` = auto-detect
  per function), and last-resort `loom_dispatch_base_overrides`.

- **`jobs`** — explicit per-function work items; the `discover` subcommand can also
  auto-find them.

- **`trace`** — the ground-truth source feeding P3's cross-check and the single-target
  gate: either `file` (glob of `{token, sites:{br_pc:{target:count}}}` JSON) or a
  `command` that emits the same JSON.

- **`verifier`** — the behavioural oracle interface. `unicorn` and `command` have
  implementations; the `ondevice` loader branch refers to a module that is not
  implemented. `entry` is required per run (no default address in code). `memory_layout`
  holds the arbitrary-but-explicit stack/heap/TLS/IO/trap/canary constants. `iat` is a
  user-dumped `name→addr` map. `shims` is an **extensible** libc-model registry.
  `known_vectors` are `{in, out}` I/O pairs. The sample includes synthetic vectors;
  private target vectors belong outside the repository.

- **`mode`** — `switch` (metadata-only, default) | `linear` | `full`.
  The loader **refuses** `linear`/`full` unless a verifier + `known_vectors` are
  present. This checks prerequisites, not rewrite correctness; the current verifier
  does not establish equivalence of the patched IDA image. `switch` also changes
  database metadata and remains unvalidated in live IDA. **`strict_orig_check`** (default true)
  refuses to write unless current bytes match the recorded originals.

- **`regression`** — per-build validated `baseline` counts, `skip_expectations`
  (`reason → [ea]`), and `samples`. Regenerate these from **your** neutral binary;
  the shipped defaults are empty.

## Trusted inputs

Review configs before running them. `loom_trace.loom_command` and the `command` verifier
launch external programs with your user permissions; they are not sandboxed.
The Unicorn backend emulates target instructions, and its pickle dump loader can
execute Python during deserialization. Never load an untrusted pickle dump.
External programs may use the network. See the [security policy](../.github/SECURITY.md).

## Minimal config (census + classify only)

```yaml
exec_segments:
  - name: ".text"
mode: "switch"
```

That is enough to run `census` and `classify`. `resolve` additionally wants a
`trace` or `reloc_image`; `apply` wants `image`; `verify`/`regress` want
`verifier.entry` + `verifier.known_vectors`.
