"""
branchloom.dispatch_shapes — obfuscation-shape detectors.

Each module here recognises one control-flow-obfuscation *shape* and turns it into
plain, serialisable facts (dispatchers / sites / plans) for the resolve + phase
layers to consume. Every module in this package is IDA-free except through the
``adapter`` object it is handed; all target-specific values come from the AnalysisSettings,
never from a hard-coded address or segment name.

  * cff_twolevel      — two-level idx-table + tgt-table CFF (Model-0, P1 core)
  * antidisasm        — trap-BLR folding / undecodable-DCB cleanup
  * br_dispatch       — single-level CSEL/CSET + LDR + BR jump tables (Model-1)
  * ollvm_statemachine— OLLVM CMP-tree state machine (Model-2, EXPERIMENTAL)

Submodules are imported lazily (``from branchloom.dispatch_shapes import cff_twolevel``)
rather than eagerly here, so importing the package never fails on a Tier-2/3
sibling that has not been written yet.
"""

__all__ = [export_binding for export_binding in [] if export_binding in globals()]
