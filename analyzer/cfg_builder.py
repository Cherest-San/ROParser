"""
CFG Builder
Control flow graph construction module

Builds complete CFG based on LSE and RVSA results
"""

import logging
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict

from miasm.core.asmblock import AsmCFG, AsmBlock, LocKey
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container

from utils.constants import AddressPair, CONSTRAINT_NEXT, CONSTRAINT_TO, GADGETS_MAX_LEN

logger = logging.getLogger(__name__)


class CFGBuilder:
    """
    Control flow graph builder

    Builds CFG based on address pair sequences and branch information
    """

    def __init__(
            self,
            loc_db: LocationDB,
            machine=None,
            loader=None
    ):
        """
        Initialize CFG builder

        Args:
            loc_db: Location database
            machine: Miasm machine instance for disassembly
            loader: CLE loader for memory access
        """
        self.loc_db = loc_db
        self.machine = machine
        self.loader = loader
        self.cfg = AsmCFG(loc_db=loc_db)

        self.base = 64
        if self.machine.name == 'x86_64':
            self.base = 64
        elif self.machine.name == 'x86':
            self.base = 32

        # Address pair to basic block mapping
        self.address_to_block: Dict[AddressPair, AsmBlock] = {}
        self.address_to_loc_key: Dict[AddressPair, LocKey] = {}

        # Basic block mapping
        self.block_map: Dict[LocKey, List[AddressPair]] = {}

        # Edge constraints
        self.edge_constraints: Dict[Tuple[LocKey, LocKey], str] = {}

        self.loc_key_counter = 0

    def create_block(self, address_pair: AddressPair) -> AsmBlock:
        """
        Create basic block for address pair

        Args:
            address_pair: Address pair

        Returns:
            Created basic block
        """
        if address_pair in self.address_to_block:
            return self.address_to_block[address_pair]

        self.loc_key_counter += 1
        loc_key = LocKey(self.loc_key_counter)

        block = AsmBlock(loc_db=self.loc_db, loc_key=loc_key)
        self.cfg.add_block(block)

        self.address_to_block[address_pair] = block
        self.address_to_loc_key[address_pair] = loc_key
        self.block_map[loc_key] = [address_pair]

        return block

    def add_edge(
            self,
            from_address: AddressPair,
            to_address: AddressPair,
            constraint: str = CONSTRAINT_TO
    ):
        """
        Add CFG edge

        Args:
            from_address: Source address pair
            to_address: Target address pair
            constraint: Edge constraint type
        """
        from_block = self.create_block(from_address)
        to_block = self.create_block(to_address)

        from_key = from_block.loc_key
        to_key = to_block.loc_key

        # Add edge
        self.cfg.add_edge(from_key, to_key, constraint)
        self.edge_constraints[(from_key, to_key)] = constraint

        # Update block mapping
        if to_address not in self.block_map[to_key]:
            self.block_map[to_key].append(to_address)

    def create_raw_cfg(
            self,
            visited_nodes: List[AddressPair],
            visited_edges: List[Tuple[AddressPair, AddressPair]],
            executor: Optional[Any] = None,
            stack_values: Optional[Dict[int, int]] = None
    ) -> None:
        """
        Create raw CFG based on address pairs and their relationships

        Each AddressPair (RIP, RSP) represents a unique node, even if RIP is the same
        but RSP differs. Three node types are supported:

        1. NORMAL_GADGET: Normal ROP gadget (instructions before RET)
        2. CALL_EXTERNAL: External function call (creates "CALL target" node)
        3. RET_TERMINATOR: Return to stack_address (creates "RET" node, no successors)

        Args:
            visited_nodes: Ordered list of visited address pairs (RIP, RSP offset)
            visited_edges: List of edges between address pairs
            executor: LocalizedSymbolicExecutor instance for accessing gadgets
            stack_values: Optional dict mapping stack offsets to known values
                          Enables POP -> MOV conversion for clearer control flow
        """
        if not self.machine:
            logger.error("Machine not set in CFGBuilder, cannot disassemble instructions")
            return

        if not self.loader:
            logger.error("Loader not set in CFGBuilder, cannot access memory")
            return

        # Get stack_address from executor for identifying RET nodes
        stack_address = getattr(executor, 'stack_address', 0) if executor else 0

        logger.info(f"Creating raw CFG with {len(visited_nodes)} nodes and {len(visited_edges)} edges")

        # Get the external function addresses to identify CALL instruction
        call_targets = getattr(executor, 'external_functions', 0) if executor else set()

        # Step 1: Create blocks for each node based on its type
        for address_pair in visited_nodes:
            rip_addr, rsp_offset = address_pair

            # Determine node type
            if not rip_addr or rip_addr == stack_address:
                # RET node: return to stack address
                self._create_ret_node(address_pair)
            elif rip_addr in call_targets:
                # CALL node: appears as source but not as target
                # This is an external function call target
                self._create_call_node(address_pair)
            else:
                # Normal gadget: disassemble and create node
                self._create_gadget_node(address_pair, executor)

        edge_map = defaultdict(list)
        for from_addr, to_addr in visited_edges:
            edge_map[from_addr].append(to_addr)

        for node in visited_nodes:
            from_rip, from_rsp = node
            successors = edge_map.get(node, [])

            if not successors:
                continue

            next_successor = min(successors, key=lambda s: abs(s[1] - from_rsp))

            for successor in successors:
                constraint = CONSTRAINT_NEXT if successor == next_successor else CONSTRAINT_TO
                self.add_edge(node, successor, constraint)
                logger.debug(f"Added edge: ({node}) -> ({successor})")

        logger.info(f"Raw CFG creation completed: {len(self.cfg.blocks)} blocks, "
                    f"{len(list(self.cfg.edges()))} edges")

    def _create_ret_node(self, address_pair: AddressPair) -> None:
        """
        Create a RET terminator node

        Args:
            address_pair: Address pair for the RET node
        """
        block = self.create_block(address_pair)
        mn = self.machine.mn()
        asm_str = f"RET"
        instr = mn.fromstring(asm_str, self.loc_db, self.base)
        block.addline(instr)
        logger.debug(f"Created RET node for {address_pair}")

    def _create_call_node(self, address_pair: AddressPair) -> None:
        """
        Create a CALL external function node

        Args:
            address_pair: Address pair for the CALL node
            target_addr: Target function address
        """
        block = self.create_block(address_pair)

        # Create CALL instruction
        target_addr = address_pair[0]

        if self.machine:
            mn = self.machine.mn()
            asm_str = f"CALL {hex(target_addr)}"
            instr = mn.fromstring(asm_str, self.loc_db, self.base)
            block.addline(instr)
            logger.debug(f"Added CALL instruction: {instr} to {hex(target_addr)}")
        else:
            logger.debug(f"Created CALL node to {hex(target_addr)} (no machine, placeholder only)")

    def _create_gadget_node(
            self,
            address_pair: AddressPair,
            executor: Optional[Any],
    ) -> None:
        """
        Create a normal gadget node with instructions before RET

        Args:
            address_pair: Address pair (RIP, RSP)
            executor: LSE executor for accessing preloaded gadgets
        """
        rip_addr, rsp_offset = address_pair

        # Get gadget bytes from executor's preloaded gadgets or split in memory
        if executor and hasattr(executor, 'gadgets') and rip_addr in executor.gadgets:
            gadget_bytes = executor.gadgets[rip_addr]
            logger.debug(f"Using preloaded gadget for {hex(rip_addr)} ({len(gadget_bytes)} bytes)")
        elif executor and hasattr(executor, 'split_gadget'):
            gadget_bytes = executor.split_gadget(rip_addr)
            if gadget_bytes:
                logger.debug(f"Split gadget at {hex(rip_addr)} ({len(gadget_bytes)} bytes)")
            else:
                logger.warning(f"Failed to split gadget at {hex(rip_addr)}")
                # Create empty block for failed gadget
                self.create_block(address_pair)
                return
        else:
            raise ValueError("Failed to get gadget in cfg_builder")

        # Disassemble gadget and get instructions before RET
        instructions = self._disassemble_gadget(address_pair, gadget_bytes, executor)

        # Create block and add instructions
        block = self.create_block(address_pair)

        for instr in instructions:
            block.addline(instr)

        logger.debug(f"Created gadget node at {hex(rip_addr)} with {len(instructions)} instructions")

    def _load_gadget_from_memory(self, address: int) -> Optional[bytes]:
        """
        Load gadget bytes from memory

        Args:
            address: Start address of gadget

        Returns:
            Gadget bytes, None if failed
        """
        try:
            memory = self.loader.memory
            code = memory.load(address, GADGETS_MAX_LEN)

            # Add HLT (0xF4) as terminator to prevent infinite disassembly
            return code + b'\xF4'
        except Exception as e:
            logger.debug(f"Failed to load gadget from memory at {hex(address)}: {e}")
            return None

    def _disassemble_gadget(
            self,
            address: AddressPair,
            gadget_bytes: bytes,
            executor: Optional[Any],
    ) -> List:
        """
        Disassemble gadget bytes and return instructions before RET.

        Args:
            address: Address pair (RIP, RSP) for logging
            gadget_bytes: Raw bytes of the gadget
            executor: LSE executor; used to look up pre-processed instruction blocks

        Returns:
            List of assembly instructions (RET excluded)
        """
        try:
            # Get preload gadget with POP instruction
            if executor and hasattr(executor, 'preload_instr') and address in executor.preload_instr:
                mblock = executor.preload_instr[address]
            else:
                container = Container.from_string(gadget_bytes, self.loc_db)
                mdis = self.machine.dis_engine(container.bin_stream, loc_db=self.loc_db)
                mblock = mdis.dis_block(0)

            instructions = []

            # Gadget preprocessing
            for line in mblock.lines:
                if 'RET' in line.name:
                    logger.debug(f"Found RET at {hex(address[0])}, stopping (RET not included)")
                    break
                elif 'HLT' in line.name:
                    break
                else:
                    instructions.append(line)

            return instructions

        except Exception as e:
            logger.warning(f"Failed to disassemble gadget at {hex(address[0])}: {e}")
            return []

    def normalize(self) -> None:
        """
        Normalize CFG: Merge linear gadget sequences into basic blocks.

        This function iterates through the CFG and merges Block A and Block B if:
        1. Block A has exactly one successor (Block B)
        2. Block B has exactly one predecessor (Block A)
        3. Block A != Block B (avoid self-loops)

        It updates edge constraints, instruction lists, and internal block mappings.
        """
        logger.info("Starting CFG normalization (block merging)...")

        changed = True
        while changed:
            changed = False
            # Create a snapshot of blocks to iterate safely while modifying the graph
            # We filter out blocks that might have been removed in previous iterations
            current_blocks = list(self.cfg.blocks)

            for block_a in current_blocks:
                # Check if block_a still exists (it might have been merged into another block)
                if block_a not in self.cfg.blocks:
                    continue

                loc_a = block_a.loc_key

                # Check Successors of A
                succs_a = list(self.cfg.successors(loc_a))
                if len(succs_a) != 1:
                    continue

                loc_b = succs_a[0]

                # Avoid merging self-loops
                if loc_a == loc_b:
                    continue

                # Get Block B object
                try:
                    block_b = self.cfg.loc_key_to_block(loc_b)
                except ValueError:
                    # Handle case where block lookup fails (should not happen in consistent graph)
                    continue

                # Check Predecessors of B
                preds_b = list(self.cfg.predecessors(loc_b))
                if len(preds_b) != 1:
                    continue

                # Confirm the single predecessor is indeed A
                if preds_b[0] != loc_a:
                    continue

                # === Perform Merge: B into A ===
                logger.debug(f"Merging block {loc_b} into {loc_a}")

                # 1. Transfer instructions: Append B's lines to A
                block_a.lines.extend(block_b.lines)

                # 2. Transfer outgoing edges: A inherits B's successors
                succs_b = list(self.cfg.successors(loc_b))
                for loc_c in succs_b:
                    # Retrieve original constraint from B->C
                    constraint = self.edge_constraints.get((loc_b, loc_c), CONSTRAINT_TO)

                    # Add edge A->C with same constraint
                    self.cfg.add_edge(loc_a, loc_c, constraint)
                    self.edge_constraints[(loc_a, loc_c)] = constraint

                # 3. Update Mappings
                # Move AddressPairs from B to A in block_map
                addrs_b = self.block_map.pop(loc_b, [])
                self.block_map[loc_a].extend(addrs_b)

                # Update address_to_* mappings for all addresses in B
                for addr in addrs_b:
                    self.address_to_loc_key[addr] = loc_a
                    self.address_to_block[addr] = block_a

                # 4. Cleanup: Remove B and old edges
                # Remove edge A->B
                self.cfg.del_edge(loc_a, loc_b)
                self.edge_constraints.pop((loc_a, loc_b), None)

                # Remove edges B->C (constraints only, del_block handles graph edges)
                for loc_c in succs_b:
                    self.edge_constraints.pop((loc_b, loc_c), None)

                # Remove Block B from graph
                self.cfg.del_block(block_b)

                # Set flag to restart scan (naive but safe approach for graph modification)
                changed = True
                break

        # Phase 2: Remove empty blocks (blocks with no instructions)
        changed = True
        while changed:
            changed = False
            for block in list(self.cfg.blocks):
                if block.lines:
                    continue

                loc_empty = block.loc_key
                preds = list(self.cfg.predecessors(loc_empty))
                succs = list(self.cfg.successors(loc_empty))

                # Redirect each predecessor's edge to all successors
                for loc_pred in preds:
                    constraint = self.edge_constraints.pop((loc_pred, loc_empty), CONSTRAINT_TO)
                    self.cfg.del_edge(loc_pred, loc_empty)

                    for loc_succ in succs:
                        self.cfg.add_edge(loc_pred, loc_succ, constraint)
                        self.edge_constraints[(loc_pred, loc_succ)] = constraint

                # Update address mappings: merge into first successor or discard
                addrs = self.block_map.pop(loc_empty, [])
                if succs:
                    try:
                        target_block = self.cfg.loc_key_to_block(succs[0])
                    except ValueError:
                        target_block = None

                    if target_block:
                        for addr in addrs:
                            self.address_to_loc_key[addr] = succs[0]
                            self.address_to_block[addr] = target_block
                        self.block_map.setdefault(succs[0], []).extend(addrs)
                else:
                    for addr in addrs:
                        self.address_to_loc_key.pop(addr, None)
                        self.address_to_block.pop(addr, None)

                # Cleanup: remove outgoing edges and the empty block
                for loc_succ in succs:
                    self.edge_constraints.pop((loc_empty, loc_succ), None)

                self.cfg.del_block(block)
                changed = True
                break

        logger.info(f"Normalization completed. Final block count: {len(list(self.cfg.blocks))}")

    def get_block(self, address_pair: AddressPair) -> Optional[AsmBlock]:
        """Return the AsmBlock mapped to an address pair, or None."""
        return self.address_to_block.get(address_pair)

    def get_loc_key(self, address_pair: AddressPair) -> Optional[LocKey]:
        """Return the LocKey mapped to an address pair, or None."""
        return self.address_to_loc_key.get(address_pair)

    def get_cfg(self) -> AsmCFG:
        """Return the built AsmCFG."""
        return self.cfg

    def clear(self):
        """Reset all internal state and start with a fresh empty CFG."""
        self.cfg = AsmCFG(loc_db=self.loc_db)
        self.address_to_block.clear()
        self.address_to_loc_key.clear()
        self.block_map.clear()
        self.edge_constraints.clear()
        self.loc_key_counter = 0
