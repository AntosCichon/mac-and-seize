# Web interface (planned)

This package is a **documented stub**. It is not implemented yet, but the rest
of the codebase is structured so it can be dropped in without moving business
logic.

## Intended design

The browser UI (served on `localhost`) is just another *adapter* over the
discovered **modules** and their shared **action registry**, exactly like the
interactive CLI. Actions come from `context.actions`; services are fetched with
`context.service("<key>")`. See `mac_and_seize/modules/README.md` for how
modules register these.

The interactive CLI already enumerates `context.actions` to render a command
tree + input prompts; the web UI should enumerate the same registry to render a
list of actions + input forms, and POST the collected values back to
`action.run(context, values)`. Define an action once, get it in both
front-ends.

```
        modules/<name>/  (services + actions, auto-discovered)
                               |
                context.actions / context.service(key)
                               ^
                 +-------------+-------------+
                 |                           |
        +--------+--------+         +--------+--------+
        |   cli (Typer)   |         |  server (web)   |
        +-----------------+         +-----------------+
```

### Contract

`create_app(context: AppContext)` should:

1. Take an already-built `AppContext` (config + timer + discovered
   services/actions).
2. Return a configured web app (FastAPI recommended - it integrates natively
   with the existing Pydantic models; Flask is a lighter alternative).
3. Prefer driving routes off `context.actions` (`action.run(context, values)`)
   so new modules appear automatically. If a route needs a service directly,
   fetch it with `context.service("<key>")`. No route should import a module's
   internal `net`/`service` code or contain business logic.

### Suggested layout when implemented

```
server/
  app.py                # create_app() factory (this file's real version)
  routes/               # thin HTTP handlers -> services
  web/
    templates/          # Jinja2 templates
    static/             # css / js / assets
```

### Wiring

The CLI already has a `serve` command placeholder in
`mac_and_seize/cli/commands/serve.py`. Once `create_app` is implemented, that
command boots the chosen ASGI/WSGI server (e.g. `uvicorn`) using
`config.server.listen_address` and `config.server.port`.
