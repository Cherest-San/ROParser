"""
Memory Callback Handler for Miasm Symbolic Execution

Provides a clean encapsulation of memory access simulation without global variables.
Follows SOLID principles with single responsibility for callback handling.
"""

import logging
from typing import List, Optional, Set

import cle
from miasm.expression.expression import ExprId, ExprInt, ExprOp, ExprMem, ExprCond
from miasm.expression.simplifications import expr_simp
from miasm.ir.symbexec import SymbolicExecutionEngine

from .rvsa import ReducedValueSetAnalyzer
from utils.constants import X86_64_REGS, X86_32_REGS
from utils.helpers import pack, unpack, describe_address

logger = logging.getLogger(__name__)


class MemoryCallbackHandler:
    """
    Miasm memory callback handler

    Encapsulates memory access simulation context (loader, ROP chain, symbolic engine)
    while maintaining compatibility with Miasm's callback interface.

    Usage:
        handler = MemoryCallbackHandler(loader, rop_chain)
        simplifier.expr_simp_cb[ExprMem].insert(0, handler)

        # During execution:
        handler.set_engine(symbolic_engine)
    """

    def __init__(self, loader: cle.Loader, rop_chain: List[int], value_set_analyzer):
        """
        Initialize callback handler

        Args:
            loader: CLE loader for memory access
            rop_chain: ROP gadget address list
        """
        self.loader = loader
        self.rop_chain = rop_chain
        self.see: Optional[SymbolicExecutionEngine] = None
        self.vsa: ReducedValueSetAnalyzer = value_set_analyzer

    def set_engine(self, see: SymbolicExecutionEngine) -> None:
        """
        Inject current symbolic execution engine instance

        Args:
            see: The symbolic execution engine being used
        """
        self.see = see

    def __call__(self, e_s, e):
        """
        Callback function for Miasm expression simplifier

        Handles memory access simulation during symbolic execution.
        Called automatically when Miasm encounters ExprMem expressions.

        Args:
            e_s: Expression simplifier context (unused)
            e: Expression to simplify (expected to be ExprMem)

        Returns:
            ExprInt with loaded data
        """
        logger.debug('-----------MEMORY-----------')

        if isinstance(e, ExprMem):
            if isinstance(e.ptr, ExprId):
                return self._handle_register_ptr(e)
            elif isinstance(e.ptr, ExprInt):
                size = e.ptr.size
                addr = e.ptr.arg

                # Check if address is within valid memory range before loading
                if describe_address(self.loader.memory, addr):
                    data = unpack(self.loader.memory.load(addr, size // 8), size)
                else:
                    logger.warning(f"Address {hex(addr)} not in loader memory range, returning 0")
                    data = 0
                return ExprInt(data, size)
            elif isinstance(e.ptr, ExprOp):
                if self.vsa.check_vsa_symbol(e.ptr):
                    return e

                symbol = self.see.symbols
                table_query_res = self.vsa.identify_tabel_query(e.ptr)
                if table_query_res:
                    return self.vsa.get_new_symbol(e.ptr, e.size, symbol)

                ptr = e.ptr
                for i in ptr.get_r():
                    if isinstance(i, ExprId):
                        if isinstance(symbol[i], ExprInt):
                            env = {i: symbol[i]}
                            ptr = ptr.replace_expr(env)
                            ptr = expr_simp(ptr)
                if isinstance(ptr, ExprInt):
                    if describe_address(self.loader.memory, ptr.arg):
                        data = unpack(self.loader.memory.load(ptr.arg, e.size // 8), e.size)
                        return ExprInt(data, e.size)
                    else:
                        return ExprInt(0, e.size)
                else:
                    return ExprInt(0, e.size)


        return ExprInt(0, e.size)

    def _handle_register_ptr(self, e: ExprMem):
        """
        Handle register-based pointer dereference

        Args:
            e: ExprMem with ExprId pointer

        Returns:
            Loaded data value
        """
        name = e.ptr.name
        size = e.ptr.size
        regs = X86_64_REGS if e.size == 64 else X86_32_REGS
        rsp = regs[2]

        # RSP handling - read from ROP chain
        if name == rsp:
            return self._handle_rsp_access(name, size, e.size)

        # Other registers - read from memory
        if name in X86_64_REGS[2:] or name in X86_32_REGS[2:]:
            return self._handle_memory_register_access(name, size, e.size)

        return ExprInt(0, e.size)

    def _handle_address_from_chain(self, rsp, size):
        word_size = size // 8

        # Unaligned access: align backward (toward lower address)
        if rsp % word_size != 0:
            aligned_rsp = (rsp // word_size) * word_size
            index = aligned_rsp // word_size
            if 0 <= index < len(self.rop_chain):
                data = self.rop_chain[index]
            else:
                data = self.rop_chain[-1]
            logger.debug(
                f"Unaligned RSP {hex(rsp)}, aligned backward to {hex(aligned_rsp)} "
                f"(index {index}), value={hex(data)}"
            )

        # Within ROP chain bounds
        elif rsp // word_size < len(self.rop_chain):
            data = self.rop_chain[rsp // word_size]

        # Switch case overflow - return last address
        else:
            data = self.rop_chain[-1]

        return data

    def _handle_rsp_exprcond(self, cond: ExprCond, size: int) -> ExprCond:
        """
        Handle RSP access within conditional expressions

        When RSP register contains a conditional expression, resolve both branches
        from the ROP chain and return the resolved conditional expression.

        Args:
            cond: Conditional expression containing src1, src2 and cond operator
            size: Data bit width (32 or 64)

        Returns:
            Resolved conditional expression with src1/src2 from ROP chain

        Raises:
            TypeError: If cond.src1 or cond.src2 is not ExprInt type
        """
        logger.debug(f'Handling RSP conditional expression: {cond}, bit width: {size}bit')

        # Validate branch types of the conditional expression
        if not isinstance(cond.src1, ExprInt):
            logger.error(f'Invalid src1 type in ExprCond: expected ExprInt, got {type(cond.src1)}')
            return cond
            # raise TypeError(f'ExprCond.src1 must be ExprInt, got {type(cond.src1).__name__}')

        if not isinstance(cond.src2, ExprInt):
            logger.error(f'Invalid src2 type in ExprCond: expected ExprInt, got {type(cond.src2)}')
            return cond
            # raise TypeError(f'ExprCond.src2 must be ExprInt, got {type(cond.src2).__name__}')

        # Extract raw offsets from conditional expression
        offset_src1 = cond.src1.arg
        offset_src2 = cond.src2.arg

        logger.debug(f'Raw offsets: src1_offset={hex(offset_src1)}, src2_offset={hex(offset_src2)}')

        # Resolve actual address values from ROP chain
        resolved_src1 = self._handle_address_from_chain(offset_src1, size)
        resolved_src2 = self._handle_address_from_chain(offset_src2, size)

        logger.debug(f'Resolved addresses: src1={hex(resolved_src1)}, src2={hex(resolved_src2)}')
        logger.debug(f'Condition operator: {cond.cond}')

        # Build new conditional expression
        resolved_expr = ExprCond(
            cond.cond,
            ExprInt(resolved_src1, size),
            ExprInt(resolved_src2, size)
        )
        logger.debug(f'Final conditional expression: {resolved_expr}')

        return resolved_expr

    def _handle_rsp_access(self, name: str, ptr_size: int, size: int):
        """
        Handle RSP register access (stack pointer)

        Reads data from the ROP chain based on current RSP offset.

        Args:
            name: Register name (RSP/ESP)
            ptr_size: Register size in bits

        Returns:
            Data from ROP chain
        """
        rsp = X86_64_REGS[2] if ptr_size == 64 else X86_32_REGS[2]

        # TODO: ADC instructions??
        if isinstance(self.see.symbols[ExprId(name, ptr_size)], ExprOp):
            return self.see.symbols[ExprId(name, ptr_size)]

        # Handle ExprCond for conditional branch
        if isinstance(self.see.symbols[ExprId(name, ptr_size)], ExprCond):
            return self._handle_rsp_exprcond(self.see.symbols[ExprId(name, ptr_size)], ptr_size)

        data_rsp = self.see.symbols[ExprId(rsp, ptr_size)].arg
        data = self._handle_address_from_chain(data_rsp, ptr_size)

        logger.debug(f'{name}:{hex(data_rsp)}:{hex(data_rsp // (ptr_size // 8))}')
        logger.debug(f'read data from {name}:{hex(data)}')

        return ExprInt(data, size)

    def _handle_memory_register_access(self, name: str, ptr_size: int, size: int):
        """
        Handle memory access through non-stack registers

        Attempts to read from the loader's memory at the address
        contained in the register.

        Args:
            name: Register name
            ptr_size: Access size in bits

        Returns:
            Data read from memory or 0 if address invalid
        """
        ptr = self.see.symbols[ExprId(name, ptr_size)]

        if self.vsa.check_vsa_symbol(ptr):
            return ExprMem(ptr, size)

        # Concrete address - direct memory access
        elif isinstance(ptr, ExprInt):
            if describe_address(self.loader.memory, ptr.arg):
                data = unpack(self.loader.memory.load(ptr.arg, ptr_size // 8), ptr_size)

            else:
                data = 0

            logger.debug(f'{name}:{hex(ptr.arg)}:{data}')

        # Symbolic address - try simplification
        else:
            data = self._handle_symbolic_address(ptr, ptr_size, size)
            return data

        logger.debug(f'read data from {name}:{hex(data)}')
        return ExprInt(data, size)

    def _handle_symbolic_address(self, ptr: ExprOp, ptr_size: int, size: int):
        """
        Handle symbolic addresses by simplification

        Extracts concrete addresses from symbolic expressions
        by substituting all ExprId with zeros.

        Args:
            ptr: Symbolic pointer expression
            ptr_size: Access size in bits

        Returns:
            Data read from simplified address or 0
        """
        # Extract all ExprId from expression
        ids: Set[ExprId] = set()

        def visitor(e):
            if isinstance(e, ExprId):
                ids.add(e)
            return e

        ptr.visit(visitor)

        # Substitute all symbols with zero to get base address
        env = {id: ExprInt(0, ptr_size) for id in ids}
        ptr_simp = ptr.replace_expr(env)
        ptr_simp = expr_simp(ptr_simp)

        data = 0

        # If simplification yields concrete address, try memory read
        if isinstance(ptr_simp, ExprInt):
            # if ExprMem(ptr_simp.arg) in self.see.symbols:
            #     return self.see.symbols[ExprMem(ptr_simp)]
            if describe_address(self.loader.memory, ptr_simp.arg):
                data = unpack(self.loader.memory.load(ptr_simp.arg, ptr_size // 8), ptr_size)
        else:
            logger.debug("Unsupported ptr_simp type")

        return ExprInt(data, size)

