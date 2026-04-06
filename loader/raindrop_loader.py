"""
Raindrop Loader
Loader for Raindrop obfuscated files

Processes Raindrop obfuscated binary files, extracts ROP chains and stack addresses for all obfuscated functions
"""

import logging
from typing import List, Tuple, Optional

import cle
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB
from miasm.analysis.machine import Machine
from miasm.expression.expression import ExprInt

from utils.helpers import pack
from .base_loader import BaseLoader

logger = logging.getLogger(__name__)


class RaindropLoader(BaseLoader):
    """
    Raindrop obfuscated file loader

    Identifies Raindrop obfuscated function characteristics through pattern matching
    """

    # Raindrop obfuscation characteristic pattern
    PATTERN = (
        "POP        RAX\n"
        "ADD        QWORD PTR [RAX], 0x8\n"
        "SUB        RAX, QWORD PTR [RAX]\n"
        "MOV        QWORD PTR [RAX], RSP"
    )

    def __init__(self):
        """Initialize Raindrop loader"""
        self.machine = Machine('x86_64')

    def load(
        self,
        path: str
    ) -> Tuple[Optional[cle.Loader], List[Tuple[str, int, int, Optional[int]]]]:
        """
        Load Raindrop obfuscated binary file

        Args:
            path: Binary file path

        Returns:
            (loader object, function list) tuple
        """
        try:
            loader = cle.Loader(path, auto_load_libs=False)
            record: List[Tuple[str, int, int, Optional[int]]] = []
            funcs = set()
            stack = 0

            logger.info(f"Loading Raindrop binary: {path}")
            logger.info(f"Found {len(list(loader.symbols))} symbols")

            # Iterate all symbols, find obfuscated functions
            for symbol in loader.symbols:
                if not (symbol.is_function and symbol.rebased_addr):
                    continue

                # Try to match Raindrop pattern
                func_info = self._match_raindrop_pattern(loader, symbol)
                if func_info:
                    func_name, stack_addr, begin_addr = func_info

                    # Deduplicate
                    if func_name not in funcs:
                        record.append((func_name, stack_addr, begin_addr, None))
                        funcs.add(func_name)
                        logger.debug(
                            f"Found obfuscated function: {func_name} "
                            f"at {hex(begin_addr)}, stack: {hex(stack_addr)}"
                        )

            # Sort by start address
            if record:
                record.sort(key=lambda x: x[2])

                # Set end addresses (next function's start address)
                for i in range(len(record) - 1):
                    func_name, stack_addr, start_addr, _ = record[i]
                    next_start = record[i + 1][2]
                    record[i] = (func_name, stack_addr, start_addr, next_start)

                # Initialize stack memory
                stack = record[0][1] if record else 0
                if stack:
                    self._initialize_stack_memory(loader, stack)

            if not record:
                logger.warning("No obfuscated functions found in binary")
                return loader, []

            logger.info(f"Found {len(record)} obfuscated functions")
            return loader, record

        except Exception as e:
            logger.error(f"Error loading Raindrop binary: {e}", exc_info=True)
            return None, []

    def _match_raindrop_pattern(
        self,
        loader: cle.Loader,
        symbol: cle.Symbol
    ) -> Optional[Tuple[str, int, int]]:
        """
        Match Raindrop obfuscation pattern

        Args:
            loader: CLE loader
            symbol: Symbol object

        Returns:
            If matched, return (function_name, stack_address, start_address) tuple
        """
        try:
            loc_db = LocationDB()
            code_bytes = loader.memory.load(symbol.rebased_addr, symbol.size)

            if not code_bytes:
                return None

            # Disassemble function
            code = Container.from_string(code_bytes, loc_db)
            mdis = self.machine.dis_engine(code.bin_stream, loc_db=loc_db)
            mblock = mdis.dis_block(0)
            # Check if contains Raindrop pattern
            if self.PATTERN not in str(mblock):
                return None

            # Extract stack address and start address
            # According to pattern, first PUSH contains stack address, 6th PUSH contains start address
            if len(mblock.lines) < 6:
                return None

            if mblock.lines[0].name != 'PUSH':
                return None

            if mblock.lines[5].name != 'PUSH':
                return None

            stack_expr = mblock.lines[0].args[0]
            begin_expr = mblock.lines[5].args[0]

            if not isinstance(stack_expr, ExprInt) or not isinstance(begin_expr, ExprInt):
                return None

            stack_addr = stack_expr.arg
            begin_addr = begin_expr.arg

            return (symbol.name, stack_addr, begin_addr)

        except Exception as e:
            logger.debug(f"Error matching pattern for {symbol.name}: {e}")
            return None

    def _initialize_stack_memory(
        self,
        loader: cle.Loader,
        stack_address: int
    ):
        """
        Initialize stack memory

        Args:
            loader: CLE loader
            stack_address: Stack address
        """
        try:
            memory = loader.memory
            # Initialize stack structure
            memory.store(stack_address, pack(8, 64))
            memory.store(stack_address - 8, pack(stack_address - 16, 64))
            logger.debug(f"Initialized stack memory at {hex(stack_address)}")
        except Exception as e:
            logger.warning(f"Failed to initialize stack memory: {e}")
