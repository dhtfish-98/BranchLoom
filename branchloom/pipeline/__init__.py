"""
branchloom.pipeline — Tier-3 pipeline phases.

Each phase module exposes ``execute_stage(bridge, settings, loom_in_path=None, loom_out_path=None, **loom_kw)``
returning a small JSON-able summary dict, and (where it writes to the DB) a
matching ``loom_revert(...)``. Phases are IDA-free except through the injected
``bridge`` (the single Tier-1 boundary) and never bake in a target-specific
value — every such value comes from the :class:`~branchloom.settings.AnalysisSettings`
or a call parameter.
"""

__all__ = [export_binding for export_binding in [] if export_binding in globals()]
