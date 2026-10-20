"""Подключение проекта (FastAPI) к порталу ServiceGuru.

    from sso_client import install_sso
    install_sso(app, public_paths=("/api/health",))

Включается, только если заданы переменные окружения (иначе проект работает как раньше):
  PORTAL_URL      адрес портала, например https://serviceguru-portal.onrender.com
  SSO_APP_ID      id проекта, как он указан в портале (раздел «Подключения»)
  SESSION_SECRET  случайная строка для подписи сессии проекта (или SECRET_KEY)
  SSO_SESSION_HOURS  (необязательно) срок сессии, по умолчанию 4 часа
  PORTAL_PUBLIC_KEY  (необязательно) PEM публичного ключа; иначе берётся с портала

Что добавляется: /sso/login, /sso/callback, /sso/logout, /sso/me и проверка входа для всех остальных путей.
Это файл-копия: основной лежит в portal/sso_client.py.
"""
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.request
from urllib.parse import quote

import jwt
from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

COOKIE = "sso_session"
_pub: dict = {}


def _cfg():
    portal = os.environ.get("PORTAL_URL", "").rstrip("/")
    app_id = os.environ.get("SSO_APP_ID", "")
    secret = os.environ.get("SESSION_SECRET") or os.environ.get("SECRET_KEY", "")
    return portal, app_id, secret


def enabled() -> bool:
    portal, app_id, secret = _cfg()
    return bool(portal and app_id and secret)


def _public_key() -> str:
    env = os.environ.get("PORTAL_PUBLIC_KEY", "").replace("\\n", "\n").strip()
    if env:
        return env
    if not _pub or time.time() - _pub["t"] > 3600:
        url = _cfg()[0] + "/.well-known/portal-public-key.pem"
        with urllib.request.urlopen(url, timeout=10) as r:
            _pub.update(k=r.read().decode(), t=time.time())
    return _pub["k"]


def _sign(payload: str) -> str:
    return hmac.new(_cfg()[2].encode(), payload.encode(), hashlib.sha256).hexdigest()


def make_session(claims: dict) -> str:
    ttl = float(os.environ.get("SSO_SESSION_HOURS", "4")) * 3600
    data = {"sub": claims["sub"], "name": claims.get("name", ""), "admin": bool(claims.get("admin")),
            "exp": int(time.time() + ttl)}
    payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
    return f"{payload}.{_sign(payload)}"


def read_session(cookie: str | None) -> dict | None:
    try:
        payload, sig = (cookie or "").split(".")
        if not hmac.compare_digest(sig, _sign(payload)):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data if data["exp"] > time.time() else None
    except (ValueError, KeyError):
        return None


def current_user(request: Request) -> dict | None:
    """Вошедший сотрудник: {'sub': логин, 'name': имя, 'admin': bool} или None."""
    return read_session(request.cookies.get(COOKIE))


def install_sso(app, public_paths=(), public_prefixes=()):
    """public_paths/public_prefixes — пути без входа (проверки здоровья, cron с собственным секретом, вебхуки)."""
    if not enabled():
        return
    portal, app_id, _ = _cfg()
    secure = portal.startswith("https")

    @app.get("/sso/login", include_in_schema=False)
    def sso_login():
        return RedirectResponse(f"{portal}/go/{quote(app_id)}", 303)

    @app.get("/sso/callback", include_in_schema=False)
    def sso_callback(token: str = ""):
        try:
            claims = jwt.decode(token, _public_key(), algorithms=["RS256"], audience=app_id,
                                issuer=portal, options={"require": ["exp", "aud", "sub"]})
        except Exception:
            return JSONResponse({"detail": "Токен входа недействителен или устарел. Откройте проект из портала."},
                                status_code=401)
        resp = RedirectResponse("/", 303)
        resp.set_cookie(COOKIE, make_session(claims), httponly=True, secure=secure, samesite="lax",
                        max_age=int(float(os.environ.get("SSO_SESSION_HOURS", "4")) * 3600))
        return resp

    @app.get("/sso/logout", include_in_schema=False)
    def sso_logout():
        resp = RedirectResponse(portal, 303)
        resp.delete_cookie(COOKIE)
        return resp

    @app.get("/sso/me", include_in_schema=False)
    def sso_me(request: Request):
        u = current_user(request)
        return JSONResponse(u or {"detail": "Нужен вход"}, status_code=200 if u else 401)

    @app.middleware("http")
    async def sso_guard(request: Request, call_next):
        path = request.url.path
        if (path.startswith("/sso/") or path in public_paths or any(path.startswith(p) for p in public_prefixes)
                or request.method == "OPTIONS" or current_user(request)):
            return await call_next(request)
        if request.method == "GET" and not path.startswith("/api/"):
            return RedirectResponse("/sso/login", 303)
        return JSONResponse({"detail": "Нужен вход", "login_url": "/sso/login"}, status_code=401)
