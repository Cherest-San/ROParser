"""
PE Loader
PE format payload loader

Processes PE format payload JSON configuration files
"""

import logging
import json
from typing import List, Tuple, Optional
import cle

from utils.helpers import pack, unpack
from .base_loader import BaseLoader

logger = logging.getLogger(__name__)


class PELoader(BaseLoader):
    """
    PE format payload loader

    Loads PE target files and function information from JSON configuration files
    """

    def load(
        self,
        path: str
    ) -> Tuple[Optional[cle.Loader], List[Tuple[str, int, int, Optional[int]]]]:
        """
        Load PE payload configuration file

        Args:
            path: JSON configuration file path

        Returns:
            (loader object, function list) tuple
        """
        try:
            with open(path, 'r', encoding='utf-8') as fp:
                config = json.load(fp)

            pe_targets = config.get('PE_targets', [])
            target_functions = config.get('functions', [])

            if not pe_targets or len(pe_targets) < 1:
                logger.error("Invalid PE_targets in configuration")
                return None, []

            logger.info(f"Loading PE payload from {path}")
            logger.info(f"Found {len(pe_targets)} PE targets, {len(target_functions)} functions")

            # Load main PE file
            main_pe_path = pe_targets[0]['PE_path']
            loader = cle.Loader(main_pe_path, auto_load_libs=False)

            if not loader:
                logger.error(f"Failed to load main PE: {main_pe_path}")
                return None, []

            # Load other PE files and merge memory
            for target_info in pe_targets[1:]:
                target_path = target_info.get('PE_path')
                if not target_path:
                    continue

                try:
                    target_loader = cle.Loader(target_path, auto_load_libs=False)
                    target_start_addr = target_loader.main_object.min_addr
                    target_memory = target_loader.main_object.memory
                    loader.memory.add_backer(target_start_addr, target_memory)
                    logger.debug(f"Merged PE: {target_path} at {hex(target_start_addr)}")
                except Exception as e:
                    logger.warning(f"Failed to merge PE {target_path}: {e}")

            # Extract function information
            record: List[Tuple[str, int, int, Optional[int]]] = []

            for func_config in target_functions:
                func_name = func_config.get('name')
                begin_addr = func_config.get('begin')
                end_addr = func_config.get('end')

                if not all([func_name, begin_addr is not None]):
                    logger.warning(f"Invalid function config: {func_config}")
                    continue

                # Process address replacement
                replace_map = func_config.get('replace', {})
                if replace_map:
                    self._apply_replacements(loader, begin_addr, end_addr, replace_map)

                record.append((func_name, 0, begin_addr, end_addr))
                logger.debug(
                    f"Added function: {func_name} "
                    f"at [{hex(begin_addr)}, {hex(end_addr) if end_addr else 'N/A'})"
                )

            if not record:
                logger.warning("No valid functions found in configuration")
                return None, []

            logger.info(f"Successfully loaded {len(record)} functions")
            return loader, record

        except FileNotFoundError:
            logger.error(f"Configuration file not found: {path}")
            return None, []
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON configuration: {e}")
            return None, []
        except Exception as e:
            logger.error(f"Error loading PE payload: {e}", exc_info=True)
            return None, []

    def _apply_replacements(
        self,
        loader: cle.Loader,
        begin_addr: int,
        end_addr: Optional[int],
        replace_map: dict
    ):
        """
        Apply address replacements

        Args:
            loader: CLE loader
            begin_addr: Start address
            end_addr: End address
            replace_map: Replacement mapping {hex_address: new_value}
        """
        if end_addr is None:
            return

        arch = loader.main_object.arch.name
        base = 64 if arch == 'AMD64' else 32 if arch == 'X86' else None

        if base is None:
            logger.warning(f"Unsupported architecture: {arch}")
            return

        word_size = base // 8
        replaced_count = 0

        for addr in range(begin_addr, end_addr, word_size):
            try:
                data_bytes = loader.memory.load(addr, word_size)
                data_value = unpack(data_bytes, base)
                data_hex = hex(data_value)

                if data_hex in replace_map:
                    new_value = replace_map[data_hex]
                    loader.memory.store(addr, pack(new_value, base))
                    replaced_count += 1
                    logger.debug(f"Replaced {data_hex} with {hex(new_value)} at {hex(addr)}")
            except Exception as e:
                logger.debug(f"Error replacing at {hex(addr)}: {e}")

        if replaced_count > 0:
            logger.info(f"Applied {replaced_count} address replacements")
