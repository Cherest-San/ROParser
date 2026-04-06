"""
Loader Factory

Creates corresponding loader instance based on mode
"""

import logging
from typing import Dict, Type, Tuple, Optional, List
import cle

from .base_loader import BaseLoader
from .raindrop_loader import RaindropLoader
from .pe_loader import PELoader

logger = logging.getLogger(__name__)


class LoaderFactory:
    """
    Loader factory class

    Provides unified loader creation and invocation interface
    """

    # Registered loader types
    _loaders: Dict[str, Type[BaseLoader]] = {
        'raindrop': RaindropLoader,
        'pe': PELoader,
    }

    @classmethod
    def get_loader(cls, mode: str) -> Optional[BaseLoader]:
        """
        Get loader instance for specified mode

        Args:
            mode: Loader mode ('raindrop' or 'PE')

        Returns:
            Loader instance, None if mode doesn't exist
        """
        loader_class = cls._loaders.get(mode.lower())
        if loader_class:
            return loader_class()
        return None

    @classmethod
    def get_supported_modes(cls) -> List[str]:
        """
        Get all supported modes

        Returns:
            List of supported modes
        """
        return list(cls._loaders.keys())

    @classmethod
    def register_loader(cls, mode: str, loader_class: Type[BaseLoader]):
        """
        Register new loader type

        Args:
            mode: Mode name
            loader_class: Loader class (must inherit BaseLoader)
        """
        if not issubclass(loader_class, BaseLoader):
            raise ValueError(f"Loader class must inherit from BaseLoader")
        cls._loaders[mode.lower()] = loader_class
        logger.info(f"Registered loader: {mode}")

    @classmethod
    def load(
        cls,
        path: str,
        mode: str
    ) -> Tuple[Optional[cle.Loader], List[Tuple[str, int, int, Optional[int]]]]:
        """
        Load file using loader of specified mode

        Args:
            path: File path
            mode: Loader mode

        Returns:
            (loader object, function list) tuple
        """
        loader = cls.get_loader(mode)
        if loader is None:
            logger.error(f"Unknown loader mode: {mode}")
            logger.info(f"Supported modes: {cls.get_supported_modes()}")
            return None, []

        return loader.load(path)
