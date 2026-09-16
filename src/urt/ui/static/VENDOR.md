# Vendored assets

| File | Project | Version | Source | sha256 | Licence |
|---|---|---|---|---|---|
| `htmx.min.js` | htmx (bigskysoftware/htmx) | 2.0.10 | `https://raw.githubusercontent.com/bigskysoftware/htmx/v2.0.10/dist/htmx.min.js` | `71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de` | Zero-Clause BSD |

Vendored so `/ui` works offline with no CDN and no Node build. `tests/test_ui_routes.py`
pins the hash. To upgrade: download the tagged release file, verify the hash against
the tag, update this table and the test, and re-check the served CSP still needs no
`'unsafe-eval'` / `'unsafe-inline'` (`htmx-config` in `templates/base.html` disables
`allowEval`, `allowScriptTags` and indicator style injection).

`app.css` and `report.js` are first-party.
