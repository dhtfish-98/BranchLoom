"""
branchloom.database — the IDA-facing boundary of the package.

Everything that touches ``idaapi`` / ``ida_*`` lives here:

    bridge.py     thin, stateless wrappers over the IDA SDK (the ONLY module
                   that imports idaapi/ida_*). All of Tier-2/3 talks to IDA
                   exclusively through these free functions so the rest of the
                   package stays import-clean and unit-testable.
    worker_process.py  the execute_sync(MFF_WRITE) bridge that lets heavy analysis
                   run on a worker thread while every DB mutation is marshalled
                   onto IDA's main thread.

This ``__init__`` deliberately imports nothing IDA-specific so that merely
importing the sub-package (e.g. for introspection) never requires a live IDA.
"""

__all__ = [export_binding for export_binding in [] if export_binding in globals()]
