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
from mac_and_seize.observability import get_logger

_log = get_logger(__name__)

#: Reserved key a table row may carry to request a per-row style, e.g.
#: ``{"ip": "192.168.1.50", "state": "free", ROW_STYLE_KEY: "dim"}``. Its value
#: is one of :data:`ROW_STYLES`. The key is *not* rendered as a column - both
#: the plain ``list[dict]`` tables and :meth:`Presenter.table` skip it - so a
#: module can add it to rows without changing their column layout.
#:
#: Styling is an *accent*, never the only carrier of meaning: a front-end whose
#: medium has no colour (a pipe, a log file, a monochrome terminal) drops it
#: silently, so rows must still say what they mean in their own text.
ROW_STYLE_KEY = "_style"

#: The style names a row may request under :data:`ROW_STYLE_KEY`. Front-ends map
#: these onto whatever their medium offers (an ANSI style, a curses colour pair)
#: and ignore any name they don't recognise.
ROW_STYLES = ("dim", "red", "green", "yellow", "cyan")


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


@dataclass(frozen=True)
class LayerField:
    """One editable field of a :class:`LayerType` in the packet builder.

    ``type`` is ``str`` or ``int`` and tells the front-end/module how to convert
    the entered text; ``default`` pre-fills the field (empty means "leave to the
    protocol default"). ``help`` is a one-line hint shown beside the field.
    """

    key: str
    label: str
    default: str = ""
    help: str = ""
    type: type = str


@dataclass(frozen=True)
class LayerType:
    """A protocol layer offered by the interactive packet builder.

    ``name`` is the layer's short name (e.g. ``"IP"``); ``fields`` are the
    editable fields the builder exposes for it.
    """

    name: str
    fields: list[LayerField]


@dataclass
class BuiltLayer:
    """One layer the user added in the builder: a layer name and field values.

    ``values`` maps each :class:`LayerField` key to the text the user entered
    (an empty string means the field was left at its protocol default).
    """

    name: str
    values: dict[str, str]


class Presenter(Protocol):
    """A front-end's interactive-rendering capability."""

    def table(self, rows: list[dict], columns: list[Column], *, title: str) -> None:
        """Display ``rows`` as an interactive, scrollable table.

        A row may carry :data:`ROW_STYLE_KEY` to request one of
        :data:`ROW_STYLES` for its whole line; front-ends that cannot colour
        ignore it.
        """
        ...

    def build_packet(
        self,
        catalog: list[LayerType],
        initial: list[BuiltLayer],
        *,
        title: str,
    ) -> list[BuiltLayer] | None:
        """Open an interactive packet builder and return the layers built.

        ``catalog`` lists the layer types the user may add and the fields each
        exposes; ``initial`` seeds the builder with pre-added layers (empty for
        a blank craft, or a preset's layers). Returns the ordered
        :class:`BuiltLayer` list the user assembled, or ``None`` if they
        cancelled without saving.
        """
        ...

    def notify(self, message: str) -> None:
        """Emit a best-effort status line outside the normal command/response
        flow - e.g. a background task (a scan, a long capture) finishing while
        the user is elsewhere in the session. Front-ends should show this
        regardless of the current command context. Unlike :meth:`table`, this
        is fire-and-forget: a front-end that cannot display it may drop it
        (or log it) instead of raising.
        """
        ...


class NullPresenter:
    """Default presenter: refuses interactive views.

    Used when no interactive front-end is attached (e.g. the planned web
    interface, or a headless embedding). Raises a clean :class:`ModuleError`
    rather than pretending to render.
    """

    def table(self, rows: list[dict], columns: list[Column], *, title: str) -> None:
        raise ModuleError("Interactive views are not available in this front-end.")

    def build_packet(
        self,
        catalog: list[LayerType],
        initial: list[BuiltLayer],
        *,
        title: str,
    ) -> list[BuiltLayer] | None:
        raise ModuleError("Interactive views are not available in this front-end.")

    def notify(self, message: str) -> None:
        _log.info(message)
