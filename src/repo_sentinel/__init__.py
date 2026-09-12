"""Compatibility import for the former :mod:`repo_sentinel` package name."""

from bluerayscan import __path__ as _bluerayscan_path
from bluerayscan import __version__

__path__ = _bluerayscan_path
__all__ = ["__version__"]
