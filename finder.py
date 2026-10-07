#!/usr/bin/env python3
"""A file browser whose only verb is "label this", served to your own browser.

Why a browser and not a native window: this has to run on the machine the files
are on, and those are a Mac, a Linux box and a Windows laptop in different
weeks. The standard library has an HTTP server on all three and a native GUI
toolkit on none of them that is worth shipping. So: `http.server`, one page, no
build step, no dependency — the same constraints the rest of paratia is under.

What it deliberately cannot do, and why each one is deliberate:

**It never sends file contents.** Not a preview, not the first kilobyte, not a
thumbnail. The listing is names, sizes and labels. A tool that reads your files
to help you choose which files should be unreadable has argued itself out of a
job, and the restraint has a second payoff: whatever gets hold of the token
holds a labeller, not a file-reading endpoint.

**It refuses to start inside an agent session.** Same rail as `paratia unlock`,
same honest limit: an environment variable is a courtesy, not a boundary, and
an agent can unset one. What makes it more than a courtesy here is that the
server prints its URL to a terminal and the token is never written to disk, so
a session that started it still has to get the token out of a stream it does
not own.

**It binds 127.0.0.1 and nothing else.** Not because loopback is a security
boundary against a local process — it is not, and the token is what does that
work — but because the failure mode of getting this wrong is a filesystem
index on a café network, and a default that cannot do that is worth more than
a warning that says do not do that.

**Every request carries the token, including the first.** Which means the URL
you paste has it in the query string, and your browser history now has a dead
token in it. Dead because it is regenerated per run and kept in memory only.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import secrets
import socket
import string
import sys
import threading
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

QUI = Path(__file__).resolve().parent
WEB = QUI / "web"

SPIE_AGENTE = (
    "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_PLUGIN_ROOT", "ANTHROPIC_MODEL",
    "CODEX_SANDBOX", "CODEX_HOME", "OPENAI_CODEX_SESSION", "CURSOR_AGENT", "AIDER_MODEL",
)


def dentro_un_agente() -> str | None:
    for spia in SPIE_AGENTE:
        if os.environ.get(spia):
            return spia
    return None


def _etichette():
    import importlib.util
    spec = importlib.util.spec_from_file_location("etichette", QUI / "etichette.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("etichette", mod)
    spec.loader.exec_module(mod)
    return mod


def radici() -> list[dict]:
    """Where the tree can be entered. On Windows that is the drives; everywhere
    else it is home and the root, plus whatever is mounted under /Volumes or
    /media, because the external disk is exactly the thing people forget to
    label."""
    fuori = [{"nome": "Home", "percorso": str(Path.home())}]
    if os.name == "nt":
        for lettera in string.ascii_uppercase:
            d = Path(f"{lettera}:\\")
            if d.exists():
                fuori.append({"nome": f"{lettera}:", "percorso": str(d)})
        return fuori
    fuori.append({"nome": "/", "percorso": "/"})
    for base in (Path("/Volumes"), Path("/media"), Path("/mnt")):
        if base.is_dir():
            try:
                for v in sorted(base.iterdir()):
                    if v.is_dir() and not v.name.startswith("."):
                        fuori.append({"nome": v.name, "percorso": str(v)})
            except OSError:
                pass
    return fuori


class Gestore(http.server.BaseHTTPRequestHandler):
    server_version = "paratia-finder"
    sys_version = ""
    gettone = ""

    def log_message(self, formato, *args):  # noqa: A002
        pass  # the terminal is for the URL and errors, not a request log

    # ------------------------------------------------------------- plumbing

    def _manda(self, codice: int, corpo: bytes, tipo: str) -> None:
        self.send_response(codice)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        # No external requests: same rule the paratia site follows, and here it
        # also means a labelled path cannot leave over an <img src>.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        try:
            self.wfile.write(corpo)
        except BrokenPipeError:
            pass

    def _json(self, codice: int, dati) -> None:
        self._manda(codice, json.dumps(dati, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def _autorizzato(self, q: dict) -> bool:
        dato = self.headers.get("X-Paratia") or (q.get("t", [""])[0])
        return secrets.compare_digest(dato or "", self.gettone)

    # --------------------------------------------------------------- routes

    def do_GET(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if not self._autorizzato(q):
            self._manda(403, b"paratia finder: wrong or missing token\n", "text/plain; charset=utf-8")
            return

        if u.path in ("/", "/index.html"):
            try:
                self._manda(200, (WEB / "finder.html").read_bytes(), "text/html; charset=utf-8")
            except OSError:
                self._manda(500, b"web/finder.html is missing\n", "text/plain; charset=utf-8")
            return

        if u.path == "/api/radici":
            self._json(200, {"radici": radici()})
            return

        if u.path == "/api/sfoglia":
            E = _etichette()
            dove = q.get("percorso", [str(Path.home())])[0]
            nascosti = q.get("nascosti", ["0"])[0] == "1"
            try:
                self._json(200, E.sfoglia(dove, nascosti))
            except E.Rifiuto as e:
                self._json(400, {"errore": str(e)})
            except OSError as e:
                self._json(400, {"errore": f"{type(e).__name__}: {e}"})
            return

        if u.path == "/api/piano":
            E = _etichette()
            try:
                self._json(200, {**E.piano(), "conta": E.conta()})
            except E.Rifiuto as e:
                self._json(400, {"errore": str(e)})
            return

        self._json(404, {"errore": "no such endpoint"})

    def do_POST(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if not self._autorizzato(q):
            self._manda(403, b"paratia finder: wrong or missing token\n", "text/plain; charset=utf-8")
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 64 * 1024:
                raise ValueError("body too large")
            dati = json.loads(self.rfile.read(n) or b"{}")
        except Exception as e:  # noqa: BLE001
            self._json(400, {"errore": f"unreadable body ({type(e).__name__})"})
            return

        E = _etichette()
        try:
            if u.path == "/api/segna":
                r = E.segna(dati["percorso"], dati["etichetta"], dati.get("nota", ""))
                self._json(200, r)
                return
            if u.path == "/api/togli":
                self._json(200, {"tolta": E.togli(dati["percorso"])})
                return
        except E.Rifiuto as e:
            self._json(400, {"errore": str(e)})
            return
        except KeyError as e:
            self._json(400, {"errore": f"missing field {e}"})
            return
        self._json(404, {"errore": "no such endpoint"})


def porta_libera(preferita: int) -> int:
    for p in (preferita, 0):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
            return s.getsockname()[1]
        except OSError:
            continue
        finally:
            s.close()
    raise RuntimeError("no free port on loopback")


def servi(porta: int = 8787, apri: bool = True, forza: bool = False) -> int:
    if (spia := dentro_un_agente()) and not forza:
        print(
            f"paratia finder: this looks like an agent session ({spia}), so it will not "
            f"start.\nRun it from your own terminal. The label store it writes to is not a\n"
            f"boundary, but the browsing surface does not need to exist inside a session.\n"
            f"Override with --forza if you are screenshotting it and know what that means.",
            file=sys.stderr,
        )
        return 2

    if not (WEB / "finder.html").is_file():
        print(f"paratia finder: {WEB / 'finder.html'} is missing", file=sys.stderr)
        return 2

    Gestore.gettone = secrets.token_urlsafe(24)
    porta = porta_libera(porta)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", porta), Gestore)
    url = f"http://127.0.0.1:{porta}/?t={Gestore.gettone}"

    # flush explicitly: the URL is the only way in, and stdout is block-buffered
    # whenever this is not attached to a terminal, which is exactly the case
    # when someone runs it under a launcher and waits for the line to appear.
    print(f"paratia finder on {url}", flush=True)
    print("the token lives in memory for this run only. Ctrl-C to stop.", flush=True)
    if apri:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        srv.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="label files and folders from a browser")
    p.add_argument("--porta", type=int, default=8787)
    p.add_argument("--non-aprire", dest="apri", action="store_false")
    p.add_argument("--forza", action="store_true", help="start even inside an agent session")
    a = p.parse_args(argv)
    return servi(a.porta, a.apri, a.forza)


if __name__ == "__main__":
    sys.exit(main())
