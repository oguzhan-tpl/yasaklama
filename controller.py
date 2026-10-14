from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import uvicorn
from dnslib import DNSRecord, QTYPE, RCODE, SOA, RR
from dnslib.server import BaseResolver, DNSServer
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("YASAKLAMA_DATA_DIR", str(ROOT / "data"))).resolve()
CONFIG_FILE = DATA_DIR / "config.json"
DB_FILE = DATA_DIR / "policy.sqlite3"
WEB_FILE = ROOT / "web" / "index.html"
COOKIE_NAME = "yasaklama_session"
SESSION_TTL = 8 * 60 * 60
CONFIG: dict | None = None
LOGIN_ATTEMPTS: dict[str, tuple[int, float]] = {}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_domain(value: str) -> str:
    """Canonicalize a hostname; reject URLs, IPs, wildcards and malformed labels."""
    if not isinstance(value, str):
        raise ValueError("Alan adı metin olmalı.")
    candidate = value.strip().lower()
    if not candidate or len(candidate) > 300:
        raise ValueError("Alan adı boş veya çok uzun.")
    if any(token in candidate for token in ("://", "/", "\\", "?", "#", "@", "*")):
        raise ValueError("URL değil, yalnızca alan adı girin.")
    candidate = candidate[:-1] if candidate.endswith(".") else candidate
    if not candidate or candidate.startswith(".") or ".." in candidate:
        raise ValueError("Alan adı biçimi geçersiz.")
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Alan adı IDNA biçimine dönüştürülemedi.") from exc
    if len(candidate) > 253 or "." not in candidate:
        raise ValueError("Tam alan adı girin (ör. example.com).")
    labels = candidate.split(".")
    if any(
        not label
        or len(label) > 63
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not (char.isalnum() or char == "-") for char in label)
        for label in labels
    ):
        raise ValueError("Alan adı etiketlerinden biri geçersiz.")
    if labels[-1].isdigit():
        raise ValueError("Son bölüm sayısal olamaz.")
    if all(char.isdigit() or char == "." for char in candidate):
        raise ValueError("IP adresi değil, alan adı girin.")
    return candidate


def matches_blocked_domain(query_name: str, domains: set[str]) -> bool:
    query = query_name.rstrip(".").lower()
    try:
        query = query.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return any(query == domain or query.endswith("." + domain) for domain in domains)


def password_digest(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000).hex()


def initialize_admin() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists():
        raise SystemExit("Yönetici yapılandırması zaten var; üzerine yazılmadı.")
    print("Yasaklama ilk kurulum")
    while True:
        password = getpass.getpass("En az 14 karakterlik yönetici parolası: ")
        confirmation = getpass.getpass("Parolayı tekrar girin: ")
        if len(password) < 14:
            print("Parola en az 14 karakter olmalı.")
        elif password != confirmation:
            print("Parolalar eşleşmedi.")
        else:
            break
    salt = secrets.token_bytes(16)
    cfg = {
        "password_salt": salt.hex(),
        "password_hash": password_digest(password, salt),
        "session_key": secrets.token_hex(32),
        "created_at": utc_now(),
    }
    fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(cfg, handle, indent=2)
        handle.write("\n")
    print("Yönetici hesabı hazır. Bu dosyayı ve data klasörünü koruyun.")


@contextmanager
def database() -> Iterator[sqlite3.Connection]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_FILE, timeout=8)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def initialize_database() -> None:
    with database() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS rules (
                domain TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL DEFAULT 'admin'
            );
            CREATE TABLE IF NOT EXISTS blocked_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                domain TEXT NOT NULL
            );
            """
        )


def session_cookie() -> str:
    assert CONFIG is not None
    payload = f"{int(time.time())}:{secrets.token_hex(16)}"
    encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    signature = hmac.new(bytes.fromhex(CONFIG["session_key"]), encoded.encode(), hashlib.sha256).hexdigest()
    return encoded + "." + signature


def valid_session(value: str | None) -> bool:
    if not value or "." not in value or CONFIG is None:
        return False
    try:
        encoded, signature = value.rsplit(".", 1)
        expected = hmac.new(bytes.fromhex(CONFIG["session_key"]), encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = base64.urlsafe_b64decode(padded.encode()).decode()
        issued = int(payload.split(":", 1)[0])
        return 0 <= int(time.time()) - issued <= SESSION_TTL
    except (ValueError, TypeError, UnicodeError, IndexError):
        return False


def require_admin(request: Request) -> None:
    if not valid_session(request.cookies.get(COOKIE_NAME)):
        raise HTTPException(status_code=401, detail="Oturum süresi doldu. Yeniden giriş yapın.")


def require_browser_request(request: Request) -> None:
    if request.headers.get("x-yasaklama-request") != "1":
        raise HTTPException(status_code=403, detail="İstek doğrulama başlığı eksik.")


def record_block(client_ip: str, domain: str) -> None:
    try:
        with database() as con:
            con.execute(
                "INSERT INTO blocked_queries(at, client_ip, domain) VALUES (?, ?, ?)",
                (utc_now(), client_ip[:80], domain[:253]),
            )
            con.execute(
                "DELETE FROM blocked_queries WHERE id NOT IN (SELECT id FROM blocked_queries ORDER BY id DESC LIMIT 1000)"
            )
    except sqlite3.Error:
        # DNS filtering should continue even when the optional audit write fails.
        pass


class LoginBody(BaseModel):
    password: str = Field(min_length=1, max_length=300)


class RuleBody(BaseModel):
    domain: str = Field(min_length=1, max_length=300)


class PolicyResolver(BaseResolver):
    def __init__(self, upstream: str, upstream_port: int = 53):
        self.upstream = upstream
        self.upstream_port = upstream_port
        self._cache_lock = threading.Lock()
        self._cached_domains: set[str] = set()
        self._cache_at = 0.0

    def _domains(self) -> set[str]:
        now = time.monotonic()
        if now - self._cache_at < 0.75:
            return self._cached_domains
        with self._cache_lock:
            now = time.monotonic()
            if now - self._cache_at < 0.75:
                return self._cached_domains
            with database() as con:
                latest = {row["domain"] for row in con.execute("SELECT domain FROM rules")}
            self._cached_domains = latest
            self._cache_at = time.monotonic()
            return self._cached_domains

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        try:
            canonical = qname.encode("idna").decode("ascii")
        except UnicodeError:
            canonical = qname
        if matches_blocked_domain(canonical, self._domains()):
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            reply.header.aa = 1
            reply.add_auth(
                RR(
                    rname=canonical + ".",
                    rtype=QTYPE.SOA,
                    ttl=30,
                    rdata=SOA(
                        mname="ns.invalid.",
                        rname="hostmaster.invalid.",
                        times=(30, 30, 30, 30, 30),
                    ),
                )
            )
            client_ip = "unknown"
            try:
                client_ip = handler.client_address[0]
            except (AttributeError, IndexError, TypeError):
                pass
            record_block(client_ip, canonical)
            return reply
        try:
            raw_reply = request.send(
                self.upstream,
                port=self.upstream_port,
                timeout=3,
                tcp=False,
            )
            return DNSRecord.parse(raw_reply)
        except Exception:
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply


app = FastAPI(title="Yasaklama DNS Filter", docs_url=None, redoc_url=None)


@app.on_event("startup")
def startup() -> None:
    global CONFIG
    if not CONFIG_FILE.exists():
        raise RuntimeError(
            f"Yapılandırma bulunamadı: {CONFIG_FILE}. İlk olarak python controller.py --init-admin çalıştırın."
        )
    with CONFIG_FILE.open("r", encoding="utf-8") as handle:
        CONFIG = json.load(handle)
    initialize_database()


@app.get("/")
def home() -> FileResponse:
    if not WEB_FILE.exists():
        raise HTTPException(status_code=500, detail="web/index.html bulunamadı.")
    return FileResponse(WEB_FILE)


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "service": "yasaklama-dns-filter", "time": utc_now()}


@app.post("/api/login")
def login(body: LoginBody, request: Request, response: Response) -> dict:
    require_browser_request(request)
    peer = request.client.host if request.client else "unknown"
    attempts, blocked_until = LOGIN_ATTEMPTS.get(peer, (0, 0.0))
    now = time.time()
    if blocked_until > now:
        raise HTTPException(status_code=429, detail="Çok fazla deneme. Bir dakika sonra tekrar deneyin.")
    assert CONFIG is not None
    salt = bytes.fromhex(CONFIG["password_salt"])
    matches = hmac.compare_digest(password_digest(body.password, salt), CONFIG["password_hash"])
    if not matches:
        attempts += 1
        LOGIN_ATTEMPTS[peer] = (0, now + 60) if attempts >= 6 else (attempts, 0.0)
        raise HTTPException(status_code=401, detail="Parola yanlış.")
    LOGIN_ATTEMPTS.pop(peer, None)
    response.set_cookie(
        COOKIE_NAME,
        session_cookie(),
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        max_age=SESSION_TTL,
        path="/",
    )
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request, response: Response) -> dict:
    require_browser_request(request)
    require_admin(request)
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, samesite="strict")
    return {"ok": True}


@app.get("/api/state")
def get_state(request: Request) -> dict:
    require_admin(request)
    with database() as con:
        rules = [dict(row) for row in con.execute("SELECT domain, created_at, created_by FROM rules ORDER BY domain")]
        recent = [dict(row) for row in con.execute(
            "SELECT id, at, client_ip, domain FROM blocked_queries ORDER BY id DESC LIMIT 100"
        )]
        total = con.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
    return {"rules": rules, "blocked_queries": recent, "rule_count": total}


@app.post("/api/rules")
def add_rule(body: RuleBody, request: Request) -> dict:
    require_browser_request(request)
    require_admin(request)
    try:
        domain = normalize_domain(body.domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    with database() as con:
        existing = con.execute("SELECT 1 FROM rules WHERE domain=?", (domain,)).fetchone()
        con.execute(
            "INSERT OR IGNORE INTO rules(domain, created_at, created_by) VALUES (?, ?, 'admin')",
            (domain, utc_now()),
        )
    return {"ok": True, "domain": domain, "already_existed": existing is not None}


@app.delete("/api/rules/{domain}")
def remove_rule(domain: str, request: Request) -> dict:
    require_browser_request(request)
    require_admin(request)
    try:
        domain = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    with database() as con:
        con.execute("DELETE FROM rules WHERE domain=?", (domain,))
    return {"ok": True, "domain": domain}


def main() -> None:
    parser = argparse.ArgumentParser(description="Yasaklama central DNS filtering server")
    parser.add_argument("--init-admin", action="store_true", help="Create the first admin password")
    parser.add_argument("--web-host", default="127.0.0.1")
    parser.add_argument("--web-port", type=int, default=8765)
    parser.add_argument("--dns-host", default="0.0.0.0")
    parser.add_argument("--dns-port", type=int, default=5353)
    parser.add_argument("--upstream", default="1.1.1.1")
    parser.add_argument("--upstream-port", type=int, default=53)
    parser.add_argument("--ssl-certfile", default=None)
    parser.add_argument("--ssl-keyfile", default=None)
    args = parser.parse_args()
    if args.init_admin:
        initialize_admin()
        return
    if (args.ssl_certfile is None) != (args.ssl_keyfile is None):
        raise SystemExit("--ssl-certfile ve --ssl-keyfile birlikte verilmelidir.")
    if not CONFIG_FILE.exists():
        raise SystemExit("İlk kurulum için python controller.py --init-admin çalıştırın.")
    if args.web_host not in {"127.0.0.1", "localhost", "::1"} and not args.ssl_certfile:
        print("UYARI: TLS olmadan yönetim panelini LAN'a açıyorsunuz; parolalar ağda şifrelenmez.")
        print("Yalnızca test ağında kullanın veya HTTPS sertifikası tanımlayın.")
    initialize_database()
    resolver = PolicyResolver(args.upstream, args.upstream_port)
    udp_server = DNSServer(resolver, port=args.dns_port, address=args.dns_host, tcp=False)
    tcp_server = DNSServer(resolver, port=args.dns_port, address=args.dns_host, tcp=True)
    udp_server.start_thread()
    tcp_server.start_thread()
    print(f"DNS filtre: {args.dns_host}:{args.dns_port} (UDP/TCP)")
    print(f"Yönetim paneli: {args.web_host}:{args.web_port}")
    try:
        uvicorn.run(
            app,
            host=args.web_host,
            port=args.web_port,
            ssl_certfile=args.ssl_certfile,
            ssl_keyfile=args.ssl_keyfile,
            access_log=False,
        )
    finally:
        udp_server.stop()
        tcp_server.stop()


if __name__ == "__main__":
    main()
