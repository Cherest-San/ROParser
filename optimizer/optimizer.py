"""
Optimizer Main Module
Optimizer main module

Integrates stack operation recovery, liveness analysis, and constant propagation
"""

import logging
from typing import Optional

from miasm.core.asmblock import AsmCFG
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB

from .stack_recovery import StackOperationRecovery
from .liveness_analysis import LivenessAnalyzer
from .constant_propagation import ConstantPropagator
from .block_elimination import SemanticBlockEliminator
from utils.constants import CONSTRAINT_TO, CONSTRAINT_NEXT

logger = logging.getLogger(__name__)


class Optimizer:
    """
    Optimizer

    Integrates multiple optimization strategies
    """

    def __init__(
        self,
        machine: Machine,
        loc_db: LocationDB,
        base: int,
        stack_address: Optional[int] = None,
        enable_stack_recovery: bool = True,
        enable_liveness: bool = True,
        enable_constant_propagation: bool = True,
        enable_block_elimination: bool = True,
        llm_config: Optional[dict] = None
    ):
        """
        Initialize optimizer

        Args:
            machine: Machine object
            loc_db: Location database
            base: Architecture bit width
            stack_address: Known custom stack anchor address
            enable_stack_recovery: Whether to enable stack operation recovery
            enable_liveness: Whether to enable liveness analysis
            enable_constant_propagation: Whether to enable constant propagation
            enable_block_elimination: Whether to enable block-level semantic elimination
            llm_config: LLM configuration dictionary (optional)
        """
        self.machine = machine
        self.loc_db = loc_db
        self.base = base
        self.stack_address = stack_address

        # Initialize each optimization component
        self.stack_recovery: Optional[StackOperationRecovery] = None
        if enable_stack_recovery:
            llm_config = llm_config or {}
            self.stack_recovery = StackOperationRecovery(
                api_key=llm_config.get('api_key'),
                base_url=llm_config.get('base_url'),
                model_id=llm_config.get('model_id'),
                prompt_path=llm_config.get('prompt_path'),
                stack_address=self.stack_address,
                loc_db=loc_db,
                machine=machine,
                base=base
            )

        self.liveness_analyzer: Optional[LivenessAnalyzer] = None
        if enable_liveness:
            self.liveness_analyzer = LivenessAnalyzer(base)

        self.constant_propagator: Optional[ConstantPropagator] = None
        if enable_constant_propagation:
            self.constant_propagator = ConstantPropagator(machine, loc_db, base)

        self.block_eliminator: Optional[SemanticBlockEliminator] = None
        if enable_block_elimination:
            self.block_eliminator = SemanticBlockEliminator(base)

    def optimize(self, cfg: AsmCFG) -> AsmCFG:
        """
        Execute complete optimization process

        Optimization order:
        1. Stack operation instruction recovery (LLM-based)
        2. Constant propagation
        3. Liveness analysis and dead code elimination

        Args:
            cfg: Control flow graph

        Returns:
            Optimized control flow graph
        """
        logger.info("Starting optimization process")

        # Phase 1: Constant propagation
        if self.constant_propagator:
            logger.info("Phase 1: Constant propagation")
            try:
                cfg = self.constant_propagator.propagate_cfg(cfg)
            except Exception as e:
                logger.error(f"Error in constant propagation: {e}")

        # Phase 2: Liveness analysis and dead code elimination
        if self.liveness_analyzer:
            logger.info("Phase 2: Liveness analysis and dead code elimination")
            try:
                cfg = self.liveness_analyzer.remove_dead_code(cfg)
            except Exception as e:
                logger.error(f"Error in liveness analysis: {e}")

        # Phase 3: Block-level semantic elimination
        if self.block_eliminator:
            logger.info("Phase 3: Block-level semantic elimination")
            try:
                removed = self.block_eliminator.eliminate_blocks(cfg)
                if removed:
                    logger.info(f"Phase 3: Eliminated {removed} semantically irrelevant block(s)")
            except Exception as e:
                logger.error(f"Error in block elimination: {e}")

        # Phase 4: Cleanup empty blocks created by dead code elimination
        try:
            removed = Optimizer.cleanup_empty_blocks(cfg)
            if removed:
                logger.info(f"Phase 4: Removed {removed} empty blocks after optimization")
        except Exception as e:
            logger.error(f"Error in empty block cleanup: {e}")

        # Phase 5: Merge linear chains (single-predecessor single-successor blocks)
        try:
            merged = Optimizer.merge_linear_blocks(cfg)
            if merged:
                logger.info(f"Phase 5: Merged {merged} linear block chain(s)")
        except Exception as e:
            logger.error(f"Error in linear block merging: {e}")

        # Phase 6: Stack operation instruction recovery (after block structure is stabilized)
        if self.stack_recovery:
            logger.info("Phase 6: Stack operation instruction recovery")
            try:
                self.stack_recovery.recover_cfg(cfg)
            except Exception as e:
                logger.error(f"Error in stack recovery: {e}")

        logger.info("Optimization process completed")
        return cfg

    @staticmethod
    def cleanup_empty_blocks(cfg: AsmCFG) -> int:
        """
        Remove empty blocks from CFG and redirect edges.

        Empty blocks (no instructions) may be created by dead code elimination
        when all instructions in a block are removed. This method merges them
        into successors or eliminates them entirely.

        Args:
            cfg: Control flow graph

        Returns:
            Number of removed blocks
        """
        removed_count = 0
        changed = True
        while changed:
            changed = False
            for block in list(cfg.blocks):
                if block.lines:
                    continue

                loc_empty = block.loc_key
                preds = list(cfg.predecessors(loc_empty))
                succs = list(cfg.successors(loc_empty))

                # Redirect predecessor edges to successors, preserving original constraints
                for loc_pred in preds:
                    constraint = cfg.edges2constraint.get((loc_pred, loc_empty), CONSTRAINT_TO)
                    cfg.del_edge(loc_pred, loc_empty)

                    for loc_succ in succs:
                        if (loc_pred, loc_succ) not in cfg.edges2constraint:
                            cfg.add_edge(loc_pred, loc_succ, constraint)

                # Remove outgoing edges and the empty block
                for loc_succ in succs:
                    try:
                        cfg.del_edge(loc_empty, loc_succ)
                    except Exception:
                        pass

                try:
                    cfg.del_block(block)
                except Exception:
                    pass

                removed_count += 1
                changed = True
                break  # Restart iteration after modification

        return removed_count

    @staticmethod
    def merge_linear_blocks(cfg: AsmCFG) -> int:
        """
        Merge linear block chains: if block A has exactly one successor B,
        and B has exactly one predecessor A, append B's instructions to A
        and retarget A's outgoing edges to B's successors.

        This cleans up single-predecessor/single-successor pairs left by
        prior elimination passes.

        Returns:
            Number of blocks absorbed (merged into their predecessor).
        """
        merged_count = 0
        changed = True
        while changed:
            changed = False
            for block in list(cfg.blocks):
                loc_a = block.loc_key

                # A must have exactly one successor (excluding self-loop)
                succs = [s for s in cfg.successors(loc_a) if s != loc_a]
                if len(succs) != 1:
                    continue
                loc_b = succs[0]

                # B must have exactly one predecessor (A itself)
                preds_b = list(cfg.predecessors(loc_b))
                if len(preds_b) != 1 or preds_b[0] != loc_a:
                    continue

                # Locate block B
                blk_b = next((b for b in cfg.blocks if b.loc_key == loc_b), None)
                if blk_b is None:
                    continue

                # Append B's instructions into A
                block.lines.extend(blk_b.lines)

                # Collect B's outgoing edges and constraints BEFORE any deletion.
                # Use edges2constraint directly — edge_attr() returns a display-layer
                # color dict, not the stored constraint string. Filter B's self-loop.
                b_out_edges = []
                for loc_c in cfg.successors(loc_b):
                    if loc_c == loc_b:
                        continue
                    constraint = cfg.edges2constraint.get((loc_b, loc_c), CONSTRAINT_TO)
                    b_out_edges.append((loc_c, constraint))

                # Remove A→B
                cfg.del_edge(loc_a, loc_b)

                # Remove all of B's outgoing edges (including any self-loop)
                for loc_c in list(cfg.successors(loc_b)):
                    try:
                        cfg.del_edge(loc_b, loc_c)
                    except Exception:
                        pass

                # Retarget: add A→C with B's original constraint for each C
                for loc_c, constraint in b_out_edges:
                    if (loc_a, loc_c) not in cfg.edges2constraint:
                        cfg.add_edge(loc_a, loc_c, constraint)

                # Remove B
                try:
                    cfg.del_block(blk_b)
                except Exception:
                    pass

                logger.debug(f"Merged block {loc_b} into {loc_a}")
                merged_count += 1
                changed = True
                break  # Restart: cfg structure changed

        return merged_count
