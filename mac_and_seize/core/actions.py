"""The front-end-agnostic action primitives shared by every module.

An :class:`Action` is a small declarative wrapper over a module's service layer
that also carries *parameter metadata*. Any front-end enumerates the registered
actions (``context.actions``) to present them: the interactive CLI renders them
as a command tree + prompts, and the future web interface can render them as a
list + input forms. Handlers return plain data (str / dict / list) so the same
result is equally renderable in a terminal or serializable as JSON.

Modules build their own :class:`Action` lists; this module only defines the
types. See ``mac_and_seize/modules/README.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext


@dataclass
class Param:
    """Describes a single input a front-end must collect for an action.

    When ``multiple`` is set, the input is a *collection*: the CLI accepts a
    comma-separated list (``a,b,c``) and/or inclusive integer ranges (``1-3`` ->
    ``1,2,3``), a single value being a one-item collection. The handler is then
    invoked once per value (front-ends fan out over the collection), so handlers
    can stay written for a single value.

    When ``is_flag`` is set, the param is a boolean switch: it takes no value on
    the command line (``--name``, not ``--name value``), is ``True`` when
    present and ``default`` (normally ``False``) when absent. Only meaningful
    on optional (``required=False``) params.
    """

    name: str
    help: str
    type: type = str  # ``str``, ``int`` or ``float`` (int/float parsed for you)
    required: bool = True
    default: Any = None
    multiple: bool = False
    is_flag: bool = False


@dataclass
class Action:
    """A named, described, parameterized operation over a module's services.

    ``name`` is a dotted path (e.g. ``"interface.ip4.add"``) that front-ends use
    to build a command tree: each segment before the last is a (nested) group,
    the last is the command. Names without a dot are top-level commands.

    ``handler`` receives the shared :class:`AppContext` and a ``values`` dict
    (parameter name -> parsed value) and returns plain data for rendering.
    """

    name: str
    title: str
    description: str
    handler: Callable[["AppContext", dict], Any]
    params: list[Param] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)
    requires_root: bool = False

    @property
    def command_path(self) -> str:
        """The space-separated command path, e.g. ``interface ip4 add``."""
        return self.name.replace(".", " ")

    def run(self, context: "AppContext", values: dict) -> Any:
        return self.handler(context, values)
