"""
Semantic Block Elimination Module

Implements block-level dead code elimination (Section 4.3.2 of the paper):
- Targets single-successor basic blocks with no side effects
- A block B is eliminated when DEF[B] ∩ OUT[B] = ∅
- Performs edge retargeting: redirects all predecessors to B's unique successor
"""

import logging
from typing import Dict, Set, Optional, Tuple

from miasm.core.asmblock import AsmCFG, AsmBlock, LocKey

from .liveness_analysis import LivenessAnalyzer, InstructionNode
from utils.constants import CONSTRAINT_TO

logger = logging.getLogger(__name__)


class SemanticBlockEliminator:
    """
    Semantic Block Eliminator

    Identifies and removes semantically irrelevant basic blocks that satisfy:
      Condition 1 - Absence of Side-Effects:
        ∀I ∈ B, ¬IS_SIDE_EFFECTING(I)
      Condition 2 - Transient Definitions:
        DEF[B] ∩ OUT[B] = ∅

    Only single-successor blocks are eligible; multi-successor blocks (e.g.,
    conditional branches) are never touched.
    """

    # Safety cap on iterations to avoid infinite loops on malformed CFGs
    _MAX_ITERATIONS = 1000

    def __init__(self, base: int):
        """
        Args:
            base: Architecture bit width (32 or 64)
        """
        self.base = base
        # Own liveness analyzer so liveness results are always current
        self._liveness = LivenessAnalyzer(base)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _compute_block_def(
            self,
            block: AsmBlock,
            node_map: Dict[Tuple[LocKey, int], InstructionNode],
    ) -> Set[int]:
        """DEF[B] = ∪ DEF[I] for all instructions I in B.
        None entries (capstone unresolved implicit defs) are filtered out."""
        def_b: Set[int] = set()
        for idx in range(len(block.lines)):
            node = node_map.get((block.loc_key, idx))
            if node is not None:
                def_b |= {r for r in node._def if r is not None}
        return def_b

    def _get_block_out(
            self,
            block: AsmBlock,
            node_map: Dict[Tuple[LocKey, int], InstructionNode],
    ) -> Optional[Set[int]]:
        """OUT[B] = OUT set of the last instruction in B."""
        last_idx = len(block.lines) - 1
        last_node = node_map.get((block.loc_key, last_idx))
        return last_node._out.copy() if last_node is not None else None

    def _has_side_effects(
            self,
            block: AsmBlock,
            node_map: Dict[Tuple[LocKey, int], InstructionNode],
    ) -> bool:
        """
        True if any instruction in B is side-effecting.

        An instruction node missing from node_map is treated conservatively
        as side-effecting to avoid false positives.
        """
        for idx in range(len(block.lines)):
            node = node_map.get((block.loc_key, idx))
            if node is None or node.is_side_effecting():
                return True
        return False

    def _is_semantically_irrelevant(
            self,
            block: AsmBlock,
            cfg: AsmCFG,
            node_map: Dict[Tuple[LocKey, int], InstructionNode],
    ) -> bool:
        """
        Return True iff block B satisfies all elimination criteria:

        1. Has exactly one non-self-loop successor (single-successor / linear path)
        2. No instruction in B is side-effecting  (Condition 1, trivially True if empty)
        3. DEF[B] ∩ IN[succ(B)] = ∅              (Condition 2, trivially True if empty)
        """
        loc_key = block.loc_key

        # Single-successor constraint (exclude self-loop edge if present)
        succs = list(cfg.successors(loc_key))
        succs = [s for s in succs if s != loc_key]  # filter self-loop
        if len(succs) != 1:
            return False

        # Empty block: DEF[B] = ∅ and no side effects — trivially eliminable
        # (must still satisfy single-successor constraint, checked above)
        if not block.lines:
            return True

        # Condition 1: no side-effecting instructions
        if self._has_side_effects(block, node_map):
            return False

        # Condition 2: DEF[B] ∩ IN[succ(B)] = ∅
        # Use IN[succ] directly instead of OUT[B] to exclude self-loop
        # contribution: OUT[B] = IN[succ] ∪ IN[B] when a self-loop exists,
        # which would falsely inflate the set and block valid elimination.
        succ_key = succs[0]
        succ_first_node = node_map.get((succ_key, 0))
        if succ_first_node is None:
            return True  # succ is also empty: DEF[B] = ∅, safe to eliminate

        def_b = self._compute_block_def(block, node_map)
        result = def_b & succ_first_node._in
        result -= {30, 44, 25, 254}

        return len(result) == 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def eliminate_blocks(self, cfg: AsmCFG) -> int:
        """
        Iteratively eliminate semantically irrelevant single-successor blocks.

        Algorithm (fixed-point):
          1. Run liveness analysis on the current CFG.
          2. Scan all blocks for elimination candidates.
          3. For the first candidate found:
             a. Redirect all predecessor edges to B's unique successor,
                preserving the original edge constraint.
             b. Remove B's outgoing edge and the block itself from the CFG.
          4. Repeat from step 1 until no more candidates exist.

        Blocks with no predecessors (entry-like blocks) are always skipped to
        prevent inadvertent removal of the CFG entry point.

        Returns:
            Total number of eliminated blocks.
        """
        total_eliminated = 0

        for _ in range(self._MAX_ITERATIONS):
            # Recompute liveness on the (potentially modified) CFG
            node_map = self._liveness.analyze_cfg(cfg)

            eliminated_this_round = False

            for block in list(cfg.blocks):
                loc_key = block.loc_key

                # Skip entry-like blocks (no predecessors)
                # Edge retargeting is a no-op for them and removing the entry
                # point would leave the CFG in an inconsistent state.
                preds = list(cfg.predecessors(loc_key))
                if not preds:
                    continue

                if not self._is_semantically_irrelevant(block, cfg, node_map):
                    continue

                # Get the real (non-self-loop) unique successor
                succ_key = next(
                    k for k in cfg.successors(loc_key) if k != loc_key
                )

                # Exclude self-loop from retargeting — B→B is not a real predecessor
                real_preds = [p for p in preds if p != loc_key]

                # Edge retargeting: redirect every predecessor → B to predecessor → succ
                for pred_key in real_preds:
                    # Preserve the original edge constraint (NEXT vs TO, etc.)
                    # Use edges2constraint directly — edge_attr() returns a color dict
                    # which is a display-layer conversion, not the stored constraint value.
                    original_constraint = cfg.edges2constraint.get(
                        (pred_key, loc_key), CONSTRAINT_TO
                    )

                    cfg.del_edge(pred_key, loc_key)

                    # Guard: AsmCFG.add_edge asserts constraint matches if the edge
                    # already exists. When pred already has a direct edge to succ
                    # (e.g., a conditional branch), skip re-adding to avoid
                    # an AssertionError. The predecessor can already reach the
                    # successor through the existing edge.
                    if (pred_key, succ_key) not in cfg.edges2constraint:
                        cfg.add_edge(pred_key, succ_key, original_constraint)

                # Explicitly remove self-loop before deleting the block
                if (loc_key, loc_key) in cfg.edges2constraint:
                    cfg.del_edge(loc_key, loc_key)

                # Remove B's outgoing edge
                try:
                    cfg.del_edge(loc_key, succ_key)
                except Exception:
                    pass

                # Remove the block from the CFG
                try:
                    cfg.del_block(block)
                except Exception:
                    pass

                logger.debug(
                    f"Eliminated block {loc_key}: "
                    f"{len(real_preds)} predecessor(s) retargeted to {succ_key}"
                )

                total_eliminated += 1
                eliminated_this_round = True
                # Restart: the CFG has changed, liveness must be recomputed
                break

            if not eliminated_this_round:
                # Fixed point reached
                break

        if total_eliminated > 0:
            logger.info(
                f"Block elimination: removed {total_eliminated} "
                f"semantically irrelevant block(s)"
            )

        return total_eliminated
