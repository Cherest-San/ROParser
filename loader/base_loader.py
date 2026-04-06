"""
Base Loader
Base loader abstract class

Defines common interfaces for all loaders
"""

import logging
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional
import cle

logger = logging.getLogger(__name__)


class BaseLoader(ABC):
    """
    Base loader abstract class

    All concrete loaders should inherit from this class
    """

    @abstractmethod
    def load(
        self,
        path: str
    ) -> Tuple[Optional[cle.Loader], List[Tuple[str, int, int, Optional[int]]]]:
        """
        Load binary file and extract function information

        Args:
            path: Binary file path

        Returns:
            (loader object, function list) tuple
            Function list format: [(function_name, stack_address, start_address, end_address), ...]
            Returns (None, []) if loading fails
        """
        pass

    @staticmethod
    def validate_loader_result(
        loader: Optional[cle.Loader],
        func_list: List[Tuple[str, int, int, Optional[int]]]
    ) -> bool:
        """
        Validate if loader result is valid

        Args:
            loader: Loader object
            func_list: Function list

        Returns:
            True if result is valid
        """
        if loader is None:
            return False

        if not func_list:
            return False

        # Validate function list format
        for func_info in func_list:
            if len(func_info) != 4:
                return False
            name, stack, start, end = func_info
            if not isinstance(name, str) or not isinstance(stack, int) or not isinstance(start, int):
                return False

        return True
