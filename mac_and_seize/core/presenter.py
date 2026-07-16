"""Presentation port: how a front-end renders rich, interactive views.

Most action results are plain data the front-end renders generically (a line, a
table, a numbered list). A few actions - e.g. capture's ``inspect`` - need an
*interactive* view, such as a scrollable table, that only a concrete front-end
can provide. Rather than let a module import a front-end (which would invert the
``modules -> core`` dependency arrow), the front-end supplies a :class:`Presenter`
on the :class:`~mac_and_seize.core.context.AppContext`, and modules call
``context.presenter``.

``core`` stays front-end-agnostic: it defines only the interface (and a no-op
default), never a terminal/``curses`` implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from mac_and_seize.core.errors import ModuleError


@dataclass(frozen=True)
class Column:
    """One column of a :meth:`Presenter.table` view.

    ``width`` is the base character width. ``flex`` columns share whatever
    horizontal space is left after the fixed columns, so long free-text columns
    (addresses, names) can grow with the terminal.
    """

    key: str
    label: str
    width: int
    flex: bool = False


class Presenter(Protocol):
    """A front-end's interactive-rendering capability."""

    def table(self, rows: list[dict], columns: list[Column], *, title: str) -> None:
        """Display ``rows`` as an interactive, scrollable table."""
        ...


class NullPresenter:
    """Default presenter: refuses interactive views.

    Used when no interactive front-end is attached (e.g. the planned web
    interface, or a headless embedding). Raises a clean :class:`ModuleError`
    rather than pretending to render.
    """

    def table(self, rows: list[dict], columns: list[Column], *, title: str) -> None:
        raise ModuleError("Interactive views are not available in this front-end.")
