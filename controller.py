from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import html
import ipaddress
import hmac
import json
import os
import secrets
import sqlite3
import time
import threading
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

import uvicorn
from dnslib import DNSRecord, QTYPE, RCODE, SOA, RR
from dnslib.server import BaseResolver, DNSServer
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("YASAKLAMA_DATA_DIR", str(ROOT / "data"))).resolve()
CONFIG_FILE = DATA_DIR / "config.json"
DB_FILE = DATA_DIR / "policy.sqlite3"
WEB_FILE = ROOT / "web" / "index.html"
BLOCK_PAGE_PORTAL_FILE = ROOT / "web" / "blocked.html"
COOKIE_NAME = "yasaklama_session"
SESSION_TTL = 8 * 60 * 60
CONFIG: dict | None = None
LOGIN_ATTEMPTS: dict[str, tuple[int, float]] = {}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_domain(value: str) -> str:
    """Accept a domain or pasted HTTP(S) URL; return its canonical hostname."""
    if not isinstance(value, str):
        raise ValueError("Alan adı veya web bağlantısı metin olmalı.")
    candidate = value.strip()
    if not candidate or len(candidate) > 2048:
        raise ValueError("Alan adı boş veya çok uzun.")
    if "*" in candidate or "\\" in candidate or "@" in candidate:
        raise ValueError("Wildcard veya kullanıcı bilgisi kabul edilmiyor.")
    if "://" in candidate:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Yalnızca geçerli HTTP/HTTPS bağlantıları veya alan adı girin.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Kimlik bilgisi içeren bağlantılar kabul edilmiyor.")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Bağlantıdaki port numarası geçersiz.") from exc
        candidate = parsed.hostname
    elif any(token in candidate for token in ("/", "?", "#")):
        parsed = urlsplit("https://" + candidate)
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError("Bağlantıdan alan adı çıkarılamadı.")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Bağlantıdaki port numarası geçersiz.") from exc
        candidate = parsed.hostname
    candidate = candidate.strip().lower()
    if not candidate:
        raise ValueError("Alan adı boş olamaz.")
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
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL
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


def record_audit(con: sqlite3.Connection, action: str, detail: str) -> None:
    con.execute(
        "INSERT INTO audit_events(at, actor, action, detail) VALUES (?, 'admin', ?, ?)",
        (utc_now(), action[:80], detail[:300]),
    )


BLOCK_LOG_DEDUP: dict[tuple[str, str], float] = {}
BLOCK_LOG_LOCK = threading.Lock()


def record_block(client_ip: str, domain: str) -> None:
    # Keep request storms from turning the audit database into a hot loop.
    key = (client_ip[:80], domain[:253])
    now = time.monotonic()
    with BLOCK_LOG_LOCK:
        previous = BLOCK_LOG_DEDUP.get(key)
        if previous is not None and now - previous < 10:
            return
        BLOCK_LOG_DEDUP[key] = now
        if len(BLOCK_LOG_DEDUP) > 5000:
            cutoff = now - 60
            for old_key, seen_at in list(BLOCK_LOG_DEDUP.items()):
                if seen_at < cutoff:
                    BLOCK_LOG_DEDUP.pop(old_key, None)
            while len(BLOCK_LOG_DEDUP) > 5000:
                oldest = min(BLOCK_LOG_DEDUP, key=BLOCK_LOG_DEDUP.get)
                BLOCK_LOG_DEDUP.pop(oldest, None)
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
    domain: str = Field(min_length=1, max_length=2048)


class PolicyResolver(BaseResolver):
    def __init__(self, upstream: str, upstream_port: int = 53, block_ip: str | None = None):
        self.upstream = upstream
        self.upstream_port = upstream_port
        self.block_ip = str(ipaddress.IPv4Address(block_ip)) if block_ip else None
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

    def _blocked_reply(self, request, canonical: str):
        reply = request.reply()
        reply.header.aa = 1
        # Optional HTTP landing page: only A records are mapped to the portal.
        # AAAA gets NODATA so clients can continue with the IPv4 A lookup.
        if self.block_ip and request.q.qtype == QTYPE.A:
            from dnslib import A
            reply.add_answer(RR(rname=request.q.qname, rtype=QTYPE.A, ttl=5, rdata=A(self.block_ip)))
            return reply
        if self.block_ip and request.q.qtype == QTYPE.AAAA:
            reply.header.rcode = RCODE.NOERROR
            return reply
        reply.header.rcode = RCODE.NXDOMAIN
        reply.add_auth(
            RR(
                rname=canonical + ".",
                rtype=QTYPE.SOA,
                ttl=5,
                rdata=SOA(
                    mname="ns.invalid.",
                    rname="hostmaster.invalid.",
                    times=(5, 5, 5, 5, 5),
                ),
            )
        )
        return reply

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        try:
            canonical = qname.encode("idna").decode("ascii")
        except UnicodeError:
            canonical = qname
        try:
            domains = self._domains()
        except sqlite3.Error:
            # Fail closed if the policy database cannot be read.
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply
        if matches_blocked_domain(canonical, domains):
            client_ip = "unknown"
            try:
                client_ip = handler.client_address[0]
            except (AttributeError, IndexError, TypeError):
                pass
            record_block(client_ip, canonical)
            return self._blocked_reply(request, canonical)
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


@asynccontextmanager
async def app_lifespan(_: FastAPI):
    global CONFIG
    if not CONFIG_FILE.exists():
        raise RuntimeError(
            f"Yapılandırma bulunamadı: {CONFIG_FILE}. İlk olarak python controller.py --init-admin çalıştırın."
        )
    with CONFIG_FILE.open("r", encoding="utf-8") as handle:
        CONFIG = json.load(handle)
    initialize_database()
    yield


app = FastAPI(title="Yasaklama DNS Filter", docs_url=None, redoc_url=None, lifespan=app_lifespan)
block_page_app = FastAPI(title="Yasaklama Engelleme Sayfası", docs_url=None, redoc_url=None)


@app.middleware("http")
async def admin_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["Cache-Control"] = "no-store"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@block_page_app.middleware("http")
async def block_page_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    return response


@block_page_app.get("/{requested_path:path}", response_class=HTMLResponse)
def blocked_landing_page(requested_path: str, request: Request) -> HTMLResponse:
    host_header = request.headers.get("host", "blocked site")
    try:
        target_host = urlsplit("//" + host_header).hostname or "blocked site"
    except ValueError:
        target_host = "blocked site"
    safe_host = html.escape(target_host[:253])
    page = f"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Erişim engellendi | Kurumunuz</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#f5f7fa;color:#1f2937;font:16px/1.55 Arial,Helvetica,sans-serif}}
.top{{height:4px;background:#174a8b}}main{{max-width:700px;margin:8vh auto;padding:0 20px}}
.card{{background:#fff;border:1px solid #d9e0e8;border-radius:2px;box-shadow:none;overflow:hidden}}
.head{{padding:20px 24px;border-bottom:1px solid #e2e7ed;display:flex;align-items:center;gap:12px}}
.mark{{width:36px;height:36px;display:grid;place-items:center;background:#174a8b;color:#fff;font-weight:bold;font-size:18px;border-radius:2px}}
.org{{font-size:12px;color:#58677a;letter-spacing:.3px;text-transform:uppercase;font-weight:bold}}h1{{font-size:24px;line-height:1.3;margin:0 0 12px;color:#174a8b;font-weight:700}}.body{{padding:26px 24px}}
.notice{{border:1px solid #d9e0e8;border-left:3px solid #174a8b;background:#f8fafc;padding:12px 14px;margin:20px 0;overflow-wrap:anywhere}}
.label{{color:#64748b;font-size:11px;text-transform:uppercase;font-weight:bold;letter-spacing:.5px}}.host{{font-weight:bold;color:#25364a;overflow-wrap:anywhere;margin-top:4px}}
p{{margin:0 0 12px}}.small{{font-size:13px;color:#66758a}}footer{{font-size:12px;color:#718096;margin-top:16px;text-align:center}}
@media(max-width:600px){{main{{margin:24px auto}}.head,.body{{padding:20px 16px}}h1{{font-size:21px}}}}
</style></head><body><div class="top"></div><main><section class="card">
<header class="head"><div class="mark" aria-hidden="true">K</div><div><div class="org">Kurum internet erişim politikası</div><div style="font-size:18px;font-weight:bold;margin-top:3px">Bilgi Teknolojileri Birimi</div></div></header>
<div class="body"><h1>Bu web sitesine erişim engellendi</h1>
<p>İstediğiniz web sitesine erişim, kurumunuzun internet kullanım politikaları doğrultusunda engellenmiştir.</p>
<div class="notice"><div class="label">Engellenen adres</div><div class="host">{safe_host}</div></div>
<p>Erişimin iş amacıyla gerekli olduğunu düşünüyorsanız kurumunuzun yetkili bilgi teknolojileri birimiyle iletişime geçin.</p>
<p class="small">Bu bildirim merkezi erişim filtresi tarafından oluşturulmuştur.</p></div></section>
<footer>Kurumsal ağ güvenliği · Yetkili kullanım ve bilgi politikaları</footer></main></body></html>"""
    return HTMLResponse(page, status_code=403)


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
    response.headers["Cache-Control"] = "no-store"
    with database() as con:
        record_audit(con, "login", "Yönetici paneline giriş")
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
    with database() as con:
        record_audit(con, "logout", "Yönetici panelinden çıkış")
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
        admin_events = [dict(row) for row in con.execute(
            "SELECT id, at, actor, action, detail FROM audit_events ORDER BY id DESC LIMIT 30"
        )]
    return {"rules": rules, "blocked_queries": recent, "rule_count": total, "admin_events": admin_events}


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
        record_audit(con, "rule_unchanged" if existing else "rule_added", domain)
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
        cursor = con.execute("DELETE FROM rules WHERE domain=?", (domain,))
        if cursor.rowcount:
            record_audit(con, "rule_removed", domain)
    return {"ok": True, "domain": domain}


def main() -> None:
    parser = argparse.ArgumentParser(description="Yasaklama central DNS filtering server")
    parser.add_argument("--init-admin", action="store_true", help="Create the first admin password")
    parser.add_argument("--web-host", default="127.0.0.1")
    parser.add_argument("--web-port", type=int, default=8765)
    parser.add_argument("--dns-host", default="0.0.0.0")
    parser.add_argument("--dns-port", type=int, default=5353)
    parser.add_argument("--block-ip", default=None, help="IPv4 address of this server; enables the HTTP block page for blocked A queries")
    parser.add_argument("--block-page-host", default="0.0.0.0")
    parser.add_argument("--block-page-port", type=int, default=80)
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
    block_ip = None
    if args.block_ip:
        try:
            block_ip = str(ipaddress.IPv4Address(args.block_ip))
        except ipaddress.AddressValueError as exc:
            raise SystemExit("--block-ip geçerli bir IPv4 adresi olmalıdır.") from exc
    resolver = PolicyResolver(args.upstream, args.upstream_port, block_ip=block_ip)
    block_page_server = None
    block_page_thread = None
    if block_ip:
        block_config = uvicorn.Config(
            block_page_app,
            host=args.block_page_host,
            port=args.block_page_port,
            log_level="warning",
            access_log=False,
        )
        block_page_server = uvicorn.Server(block_config)
        block_page_thread = threading.Thread(target=block_page_server.run, daemon=True)
        block_page_thread.start()
        deadline = time.monotonic() + 5
        while not block_page_server.started and block_page_thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not block_page_server.started:
            block_page_server.should_exit = True
            raise SystemExit(
                f"Engelleme sayfası {args.block_page_host}:{args.block_page_port} üzerinde başlamadı. "
                "Portu başka bir servis kullanıyor olabilir."
            )
        print(f"HTTP engel sayfası: {args.block_page_host}:{args.block_page_port}")
        print("Not: Bu sayfa HTTP için çalışır; HTTPS adreslerinde tarayıcı sertifika hatası gösterebilir.")
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
        if block_page_server:
            block_page_server.should_exit = True
        if block_page_thread and block_page_thread.is_alive():
            block_page_thread.join(timeout=3)


if __name__ == "__main__":
    main()
