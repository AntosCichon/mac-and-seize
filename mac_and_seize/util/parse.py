"""Small input-parsing helpers shared across modules.

``split_values`` expands one raw CLI option token into individual values,
accepting comma lists and inclusive integer ranges. It lives here (not in a
feature module) because more than one module needs it - the wired ``capture``
filters and the ``wireless`` capture/sweep specs both parse option lists this
way, and modules must never import one another (see modules/README.md §8).
"""

from __future__ import annotations


def split_values(raw: str) -> list[str]:
    """Split one raw option token into individual values.

    Accepts comma-separated lists (``a,b,c``) and inclusive integer ranges
    (``1-3`` -> ``1,2,3``, descending allowed). A single value yields a
    one-item list. Blank chunks are ignored.
    """
    values: list[str] = []
    for chunk in str(raw).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        start, sep, end = chunk.partition("-")
        if sep and start.isdigit() and end.isdigit():
            lo, hi = int(start), int(end)
            step = 1 if hi >= lo else -1
            values.extend(str(i) for i in range(lo, hi + step, step))
        else:
            values.append(chunk)
    return values
