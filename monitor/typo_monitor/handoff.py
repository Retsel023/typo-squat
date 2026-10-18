"""Compatibility import for the text-only handoff selector.

Automatic screenshot comparisons and image-based AI selection were removed.
"""

from .text_review import review_selection

__all__ = ["review_selection"]
