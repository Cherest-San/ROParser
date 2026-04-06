"""
Robust Analyzer

Integrates LSE and RVSA to implement complete robust control flow recovery framework
"""

import logging
import time

from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB

from utils.constants import *
from utils.helpers import *
from .symbolic import LocalizedSymbolicExecutor
from .cfg_builder import CFGBuilder

logger = logging.getLogger(__name__)


class CFGAnalyzer:
    """
    Robust analyzer

    Implements the complete framework described in the paper, integrating LSE and RVSA
    """

    def __init__(
            self,
            loader: cle.Loader,
            stack_address: int,
            chain_begin: Optional[int] = None,
            chain_end: Optional[int] = None
    ):
        """
        Initialize robust analyzer

        Args:
            loader: CLE loader
            stack_address: Stack address
            chain_begin: ROP chain start address
            chain_end: ROP chain end address
        """
        self.loader = loader
        self.stack_address = stack_address

        # Determine architecture
        if loader.main_object.arch.name == 'AMD64':
            self.machine_name = 'x86_64'
            self.base = 64
            self.regs = X86_64_REGS
        elif loader.main_object.arch.name == 'X86':
            self.machine_name = 'x86_32'
            self.base = 32
            self.regs = X86_32_REGS
        else:
            raise ValueError(f"Unsupported architecture: {loader.main_object.arch.name}")

        self.machine = Machine(self.machine_name)
        self.loc_db = LocationDB()

        self.rip_register = self.regs[0]  # RIP/EIP
        self.rsp_register = self.regs[2]  # RSP/ESP

        # Initialize components
        self.lse_executor = LocalizedSymbolicExecutor(
            loader,
            self.machine,
            self.loc_db,
            self.rsp_register,
            self.rip_register,
            self.base,
            chain_begin,
            chain_end,
            stack_address
        )

        self.cfg_builder = CFGBuilder(self.loc_db, self.machine, self.loader)

        # Analysis state
        self.branch_points: Set[AddressPair] = set()
        self.comparison_snapshots: List[Tuple[AddressPair, Any]] = []

    def analyze(self) -> AsmCFG:
        """
        Execute complete control flow recovery analysis

        Returns:
            Recovered control flow graph
        """
        logger.info("Starting Control Flow Recovery")

        logger.info("Starting Localized Symbolic Execution")
        t1 = time.time()
        visited_nodes, visited_edges = self.lse_executor.execute()
        t2 = time.time()
        logger.info(f"Symbolic execution completed in {t2 - t1:.2f}s")
        logger.info("Building CFG structure")
        self.cfg_builder.create_raw_cfg(visited_nodes, visited_edges, self.lse_executor)
        self.cfg_builder.normalize()

        block_count = len(self.cfg_builder.cfg.blocks)
        edge_count = len(self.cfg_builder.cfg.edges())
        instr_count = sum(len(b.lines) for b in self.cfg_builder.cfg.blocks)
        logger.info(f"Blocks: {block_count}, Edges: {edge_count}, Instructions: {instr_count}")

        logger.info("Control flow recovery completed")
        return self.cfg_builder.get_cfg()

    def optimize(self, enable_stack_recovery: bool = True,
                 enable_liveness: bool = True,
                 enable_constant_propagation: bool = True,
                 enable_block_elimination: bool = True,
                 llm_config: Optional[dict] = None) -> AsmCFG:
        """
        Optimize recovered CFG

        Args:
            enable_stack_recovery: Whether to enable stack operation recovery
            enable_liveness: Whether to enable liveness analysis
            enable_constant_propagation: Whether to enable constant propagation
            enable_block_elimination: Whether to enable block-level semantic elimination
            llm_config: LLM configuration dictionary

        Returns:
            Optimized CFG
        """
        from optimizer.optimizer import Optimizer

        cfg = self.get_cfg()

        optimizer = Optimizer(
            machine=self.machine,
            loc_db=self.loc_db,
            base=self.base,
            stack_address=self.stack_address,
            enable_stack_recovery=enable_stack_recovery,
            enable_liveness=enable_liveness,
            enable_constant_propagation=enable_constant_propagation,
            enable_block_elimination=enable_block_elimination,
            llm_config=llm_config
        )

        return optimizer.optimize(cfg)

    def get_cfg(self) -> AsmCFG:
        """Get built CFG"""
        return self.cfg_builder.get_cfg()
