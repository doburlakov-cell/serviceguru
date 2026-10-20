"""ServiceGuru Portal — единый вход для всех проектов.

Сотрудник входит здесь один раз. Клик по плитке проекта выдаёт короткоживущий подписанный токен (RS256)
и перенаправляет на проект, а тот проверяет токен публичным ключом портала и открывает свою сессию.

Окружение: SECRET_KEY, DATABASE_URL (Postgres; без него SQLite — данные пропадут при перезапуске на Render),
ADMIN_LOGIN + ADMIN_PASSWORD (создают первого администратора), PORTAL_URL (публичный адрес портала),
PORTAL_PRIVATE_KEY (необязательно: PEM-ключ; иначе генерируется и хранится в базе).
"""
import hashlib
import hmac
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from urllib.parse import quote, urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import (Boolean, Column, ForeignKey, Integer, MetaData, String, Table, Text, create_engine,
                        delete, insert, select, update)
from starlette.middleware.sessions import SessionMiddleware

BASE = os.path.dirname(__file__)
SESSION_TTL = 60 * 60 * 12          # сессия портала
TOKEN_TTL = 60                      # токен передачи в проект живёт минуту
MAX_FAILS, LOCK_SECONDS = 5, 300

db_url = os.environ.get("DATABASE_URL", "sqlite:///" + os.path.join(BASE, "portal.db"))
if db_url.startswith("postgres://"):
    db_url = "postgresql://" + db_url[len("postgres://"):]
engine = create_engine(db_url, pool_pre_ping=True)
md = MetaData()
users = Table("users", md,
              Column("id", Integer, primary_key=True),
              Column("login", String(100), unique=True, nullable=False),
              Column("name", String(200), nullable=False, default=""),
              Column("pw_hash", Text, nullable=False),
              Column("is_admin", Boolean, nullable=False, default=False),
              Column("active", Boolean, nullable=False, default=True),
              Column("last_login", Integer))
apps = Table("apps", md,
             Column("id", Integer, primary_key=True),
             Column("slug", String(60), unique=True, nullable=False),
             Column("name", String(200), nullable=False),
             Column("description", String(400), nullable=False, default=""),
             Column("url", String(500), nullable=False),
             Column("callback_path", String(200), nullable=False, default="/sso/callback"),
             Column("kind", String(10), nullable=False, default="sso"))   # sso — проект проверяет токен; link — просто ссылка
grants = Table("grants", md,
               Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
               Column("app_id", Integer, ForeignKey("apps.id", ondelete="CASCADE"), primary_key=True))
meta = Table("meta", md, Column("k", String(50), primary_key=True), Column("v", Text, nullable=False))


# ---------- пароли ----------
def hash_pw(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.scrypt(pw.encode(), salt=salt.encode(), n=2 ** 14, r=8, p=1).hex()
    return f"scrypt${salt}${h}"


def check_pw(pw: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split("$")
        got = hashlib.scrypt(pw.encode(), salt=salt.encode(), n=2 ** 14, r=8, p=1).hex()
        return hmac.compare_digest(got, h)
    except ValueError:
        return False


# ---------- ключ подписи ----------
_key_pem: bytes | None = None


def private_key_pem() -> bytes:
    global _key_pem
    if _key_pem:
        return _key_pem
    env = os.environ.get("PORTAL_PRIVATE_KEY", "").replace("\\n", "\n").strip()
    if env:
        _key_pem = env.encode()
        return _key_pem
    with engine.begin() as con:
        v = con.execute(select(meta.c.v).where(meta.c.k == "private_key")).scalar()
        if not v:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            v = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode()
            con.execute(insert(meta).values(k="private_key", v=v))
    _key_pem = v.encode()
    return _key_pem


def public_key_pem() -> bytes:
    return serialization.load_pem_private_key(private_key_pem(), None).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


# ---------- приложение ----------
def secret() -> str:
    s = os.environ.get("SECRET_KEY", "")
    if not s:
        raise RuntimeError("Не задан SECRET_KEY")
    return s


@asynccontextmanager
async def lifespan(_: FastAPI):
    secret()
    md.create_all(engine)
    private_key_pem()
    login, pw = os.environ.get("ADMIN_LOGIN", ""), os.environ.get("ADMIN_PASSWORD", "")
    with engine.begin() as con:
        if login and pw and not con.execute(select(users.c.id).limit(1)).first():
            con.execute(insert(users).values(login=login.strip().lower(), name="Администратор",
                                             pw_hash=hash_pw(pw), is_admin=True, active=True))
    yield


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
https = os.environ.get("PORTAL_URL", "").startswith("https")
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SECRET_KEY", "dev"), max_age=SESSION_TTL,
                   same_site="lax", https_only=https, session_cookie="portal_session")
templates = Jinja2Templates(directory=os.path.join(BASE, "templates"))


def render(request: Request, name: str, **ctx):
    request.session.setdefault("csrf", secrets.token_urlsafe(24))
    ctx.update(request=request, csrf=request.session["csrf"], me=getattr(request.state, "user", None))
    return templates.TemplateResponse(request, name, ctx)


def portal_url(request: Request) -> str:
    return os.environ.get("PORTAL_URL", "").rstrip("/") or str(request.base_url).rstrip("/")


# ---------- защита ----------
def current_user(request: Request):
    uid = request.session.get("uid")
    if not uid:
        return None
    with engine.connect() as con:
        row = con.execute(select(users).where(users.c.id == uid)).mappings().first()
    if not row or not row["active"]:
        request.session.clear()
        return None
    request.state.user = row
    return row


def require_user(request: Request):
    u = current_user(request)
    if not u:
        raise HTTPException(303, headers={"Location": "/login?next=" + quote(request.url.path)})
    return u


def require_admin(request: Request):
    u = require_user(request)
    if not u["is_admin"]:
        raise HTTPException(403, "Только для администратора")
    return u


async def check_csrf(request: Request, csrf: str = Form("")):
    if not csrf or not hmac.compare_digest(csrf, request.session.get("csrf", "")):
        raise HTTPException(403, "Сессия устарела, обновите страницу")


_fails: dict[str, list[float]] = {}   # ip+логин -> времена неудачных попыток


def locked(key: str) -> bool:
    now = time.time()
    recent = [t for t in _fails.get(key, []) if now - t < LOCK_SECONDS]
    _fails[key] = recent
    return len(recent) >= MAX_FAILS


def safe_next(n: str) -> str:
    return n if n.startswith("/") and not n.startswith("//") else "/"


# ---------- вход / выход ----------
@app.get("/health")
def health():
    return {"ok": True}


@app.get("/login")
def login_page(request: Request, next: str = "/"):
    if current_user(request):
        return RedirectResponse(safe_next(next), 303)
    return render(request, "login.html", next=safe_next(next), error="")


@app.post("/login")
def login(request: Request, login: str = Form(""), password: str = Form(""), next: str = Form("/"),
          _=Depends(check_csrf)):
    login = login.strip().lower()
    key = f"{request.client.host if request.client else ''}|{login}"
    if locked(key):
        return render(request, "login.html", next=safe_next(next), error="Слишком много попыток. Подождите 5 минут.")
    with engine.begin() as con:
        u = con.execute(select(users).where(users.c.login == login)).mappings().first()
        ok = bool(u and u["active"] and check_pw(password, u["pw_hash"]))
        if ok:
            con.execute(update(users).where(users.c.id == u["id"]).values(last_login=int(time.time())))
    if not ok:
        _fails.setdefault(key, []).append(time.time())
        return render(request, "login.html", next=safe_next(next), error="Неверный логин или пароль")
    request.session.clear()
    request.session.update(uid=u["id"], csrf=secrets.token_urlsafe(24))
    return RedirectResponse(safe_next(next), 303)


@app.post("/logout")
def logout(request: Request, _=Depends(check_csrf)):
    request.session.clear()
    return RedirectResponse("/login", 303)


# ---------- главная ----------
def accessible_apps(u):
    with engine.connect() as con:
        q = select(apps).order_by(apps.c.name)
        if not u["is_admin"]:
            q = q.join(grants, grants.c.app_id == apps.c.id).where(grants.c.user_id == u["id"])
        return list(con.execute(q).mappings())


@app.get("/")
def home(request: Request, u=Depends(require_user)):
    return render(request, "home.html", apps=accessible_apps(u))


@app.get("/go/{slug}")
def go(slug: str, request: Request, u=Depends(require_user)):
    with engine.connect() as con:
        a = con.execute(select(apps).where(apps.c.slug == slug)).mappings().first()
        allowed = bool(a) and (u["is_admin"] or con.execute(
            select(grants.c.app_id).where(grants.c.user_id == u["id"], grants.c.app_id == a["id"])).first())
    if not a or not allowed:
        raise HTTPException(404, "Проект не найден или нет доступа")
    if a["kind"] == "link":
        return RedirectResponse(a["url"], 303)
    now = int(time.time())
    token = jwt.encode({"iss": portal_url(request), "aud": a["slug"], "sub": u["login"], "name": u["name"],
                        "admin": bool(u["is_admin"]), "iat": now, "exp": now + TOKEN_TTL, "jti": uuid.uuid4().hex},
                       private_key_pem(), algorithm="RS256")
    target = a["url"].rstrip("/") + a["callback_path"]
    return RedirectResponse(f"{target}?{urlencode({'token': token})}", 303,
                            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@app.get("/.well-known/portal-public-key.pem")
def public_key():
    return PlainTextResponse(public_key_pem().decode(), media_type="application/x-pem-file")


# ---------- свой аккаунт ----------
@app.get("/account")
def account(request: Request, u=Depends(require_user)):
    return render(request, "account.html", msg="", error="")


@app.post("/account")
def account_save(request: Request, old: str = Form(""), new: str = Form(""), new2: str = Form(""),
                 u=Depends(require_user), _=Depends(check_csrf)):
    if not check_pw(old, u["pw_hash"]):
        return render(request, "account.html", msg="", error="Текущий пароль неверный")
    if len(new) < 8 or new != new2:
        return render(request, "account.html", msg="", error="Новый пароль: минимум 8 символов, оба поля должны совпадать")
    with engine.begin() as con:
        con.execute(update(users).where(users.c.id == u["id"]).values(pw_hash=hash_pw(new)))
    return render(request, "account.html", msg="Пароль изменён", error="")


# ---------- администрирование ----------
@app.get("/admin/users")
def admin_users(request: Request, u=Depends(require_admin)):
    with engine.connect() as con:
        rows = list(con.execute(select(users).order_by(users.c.login)).mappings())
    return render(request, "admin_users.html", rows=rows, error=request.query_params.get("error", ""))


@app.post("/admin/users")
def admin_user_create(login: str = Form(""), name: str = Form(""), password: str = Form(""),
                      u=Depends(require_admin), _=Depends(check_csrf)):
    login = login.strip().lower()
    if not login or len(password) < 8:
        return RedirectResponse("/admin/users?error=" + quote("Нужен логин и пароль от 8 символов"), 303)
    with engine.begin() as con:
        if con.execute(select(users.c.id).where(users.c.login == login)).first():
            return RedirectResponse("/admin/users?error=" + quote("Такой логин уже есть"), 303)
        uid = con.execute(insert(users).values(login=login, name=name.strip() or login, pw_hash=hash_pw(password),
                                               is_admin=False, active=True)).inserted_primary_key[0]
    return RedirectResponse(f"/admin/users/{uid}", 303)


@app.get("/admin/users/{uid}")
def admin_user(uid: int, request: Request, u=Depends(require_admin)):
    with engine.connect() as con:
        t = con.execute(select(users).where(users.c.id == uid)).mappings().first()
        if not t:
            raise HTTPException(404)
        all_apps = list(con.execute(select(apps).order_by(apps.c.name)).mappings())
        have = {r[0] for r in con.execute(select(grants.c.app_id).where(grants.c.user_id == uid))}
    return render(request, "admin_user.html", t=t, all_apps=all_apps, have=have, error="")


@app.post("/admin/users/{uid}")
async def admin_user_save(uid: int, request: Request, u=Depends(require_admin)):
    form = await request.form()
    await check_csrf(request, form.get("csrf", ""))
    is_self = uid == u["id"]
    vals = {"name": str(form.get("name", "")).strip(),
            "is_admin": True if is_self else form.get("is_admin") == "on",     # себя не лишить прав и доступа
            "active": True if is_self else form.get("active") == "on"}
    pw = str(form.get("password", ""))
    if pw:
        if len(pw) < 8:
            return RedirectResponse(f"/admin/users/{uid}", 303)
        vals["pw_hash"] = hash_pw(pw)
    chosen = {int(x) for x in form.getlist("apps") if str(x).isdigit()}
    with engine.begin() as con:
        con.execute(update(users).where(users.c.id == uid).values(**vals))
        con.execute(delete(grants).where(grants.c.user_id == uid))
        for aid in chosen:
            con.execute(insert(grants).values(user_id=uid, app_id=aid))
    return RedirectResponse("/admin/users", 303)


@app.get("/admin/apps")
def admin_apps(request: Request, u=Depends(require_admin)):
    with engine.connect() as con:
        rows = list(con.execute(select(apps).order_by(apps.c.name)).mappings())
    return render(request, "admin_apps.html", rows=rows, error=request.query_params.get("error", ""),
                  portal=portal_url(request))


def clean_slug(s: str) -> str:
    return "".join(c for c in s.strip().lower().replace(" ", "-") if c.isalnum() or c == "-")


@app.post("/admin/apps")
def admin_app_save(slug: str = Form(""), name: str = Form(""), description: str = Form(""), url: str = Form(""),
                   callback_path: str = Form("/sso/callback"), kind: str = Form("sso"), app_id: int = Form(0),
                   u=Depends(require_admin), _=Depends(check_csrf)):
    slug, url = clean_slug(slug), url.strip()
    if not slug or not name.strip() or not url.startswith(("https://", "http://")) or kind not in ("sso", "link"):
        return RedirectResponse("/admin/apps?error=" + quote("Заполните id, название и адрес (https://…)"), 303)
    vals = dict(slug=slug, name=name.strip(), description=description.strip(), url=url,
                callback_path="/" + callback_path.strip().lstrip("/"), kind=kind)
    with engine.begin() as con:
        clash = con.execute(select(apps.c.id).where(apps.c.slug == slug, apps.c.id != app_id)).first()
        if clash:
            return RedirectResponse("/admin/apps?error=" + quote("Такой id уже занят"), 303)
        if app_id:
            con.execute(update(apps).where(apps.c.id == app_id).values(**vals))
        else:
            con.execute(insert(apps).values(**vals))
    return RedirectResponse("/admin/apps", 303)


@app.post("/admin/apps/{aid}/delete")
def admin_app_delete(aid: int, u=Depends(require_admin), _=Depends(check_csrf)):
    with engine.begin() as con:
        con.execute(delete(grants).where(grants.c.app_id == aid))
        con.execute(delete(apps).where(apps.c.id == aid))
    return RedirectResponse("/admin/apps", 303)


@app.exception_handler(HTTPException)
async def http_exc(request: Request, exc: HTTPException):
    if exc.status_code == 303:
        return RedirectResponse(exc.headers["Location"], 303)
    return templates.TemplateResponse(request, "error.html", {"request": request, "code": exc.status_code,
                                                              "detail": exc.detail, "me": None, "csrf": ""},
                                      status_code=exc.status_code)
