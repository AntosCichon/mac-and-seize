"""The :class:`Route` value object.

A typed snapshot of one routing-table entry, replacing the raw ``ip -j route``
dicts that used to be passed around. It is a *pure* domain type: it carries the
route's fields and answers domain questions about itself (:meth:`is_autorecreated`)
but knows nothing about ``ip`` or subprocesses. Turning a :class:`Route` back
into an ``ip route replace`` command line is the ``ip`` adapter's job (that is
where the tool's CLI grammar belongs), keeping this model free of infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Route:
    """One route attached to an interface, for a single address family."""

    family: int
    dst: str = "default"
    gateway: str | None = None
    scope: str | None = None
    metric: int | None = None
    protocol: str | None = None

    @classmethod
    def from_json(cls, obj: dict, family: int) -> "Route":
        """Build a :class:`Route` from one ``ip -j route show`` JSON object."""
        metric = obj.get("metric")
        scope = obj.get("scope")
        return cls(
            family=family,
            dst=obj.get("dst", "default"),
            gateway=obj.get("gateway"),
            scope=str(scope) if scope is not None else None,
            metric=int(metric) if metric is not None else None,
            protocol=obj.get("protocol"),
        )

    def is_autorecreated(self) -> bool:
        """True for kernel-managed connected routes.

        The kernel recreates the connected/link route for an address on its own
        once the address is (re)assigned, so it must not be reinstalled by hand.
        Identified by ``protocol == "kernel"`` with no gateway.
        """
        return self.protocol == "kernel" and not self.gateway
