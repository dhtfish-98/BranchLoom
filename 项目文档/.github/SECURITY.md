# Security policy

branchloom reads ARM64 instructions and can change an IDA database's bytes or metadata.
The IDA pipeline and verifier integration remain unvalidated in a live IDA session.
Work on a disposable copy of a database and keep an independent backup.

## Trust boundaries

- Configured trace commands and the `command` verifier execute external programs
  with the current user's permissions. Review the command and its inputs first.
  They are not sandboxed and may access files or the network.
- The Unicorn verifier emulates target instructions. Its memory and API models
  are experimental; a successful vector check is not proof of rewrite correctness.
- The verifier's pickle segment loader uses Python `loom_pickle.read_settings`, which can execute
  code during deserialization. Only load dumps created by a source you trust.
- Configs, images, trace files and phase artifacts affect what is read or patched.
  Directory restrictions and offline operation are not enforced security boundaries.

## Reporting

Use GitHub's [private vulnerability
reporting](https://github.com/dhtfish-98/BranchLoom/security/advisories/new) for a
report that should not be public at first. Anything else can be a normal issue.

Useful in a report: the commit, the IDA version for anything in the phase layer, the
config that triggers it, and whether it was reached through the CLI or from IDA's
Python console.

## In scope

- A malformed config or artifact file (the phase chain is a series of JSON files that
  may come from someone else) that makes a phase write bytes it should not.
- A safety-layer failure — `integrity/clobber_scan.py`, `integrity/site_validation.py`,
  `integrity/image_restore.py` — that lets an aggressive rewrite proceed without its verifier
  gate, or that fails to restore the original bytes.
- A path in the CLI that writes outside the working directory without being asked to.

## Validation limits

Reports of incorrect patches or failed restoration are welcome even while the
pipeline is experimental. Include a minimal, shareable sample and the exact commit.
Do not attach private target data, credentials or an untrusted executable dump to a
public issue. See [implementation status](../IMPLEMENTATION_STATUS.md) and
[safety limits](../guides/SAFETY.md) for what has and has not been checked.
