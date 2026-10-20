"""Платформа рассылки по Telegram-аккаунтам: вход по паролю, аккаунты, контакты, кампании, тик по cron.

Окружение: APP_PASSWORD, SECRET_KEY, CRON_SECRET, DATABASE_URL (Postgres, например Neon).
"""
import asyncio
import base64
import hashlib
import hmac
import io
import os
import random
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import asyncpg
from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from telethon import TelegramClient, errors
from telethon.sessions import StringSession
from telethon.tl.types import Channel, Chat, InputPeerChannel, InputPeerChat, InputPeerUser, User

app = FastAPI()


@app.middleware("http")
async def strip_entry_prefix(request: Request, call_next):
    """Vercel может отдавать приложению путь вместе с адресом точки входа (/api/index)."""
    path = request.scope["path"]
    if path == "/api/index" or path.startswith("/api/index/"):
        request.scope["path"] = path[len("/api/index"):] or "/"
    return await call_next(request)


TICK_BUDGET = 48          # секунд на один тик (лимит функции 60)
COOKIE = "bc_auth"
COOKIE_TTL = 7 * 24 * 3600
MAX_IMAGE = 4_000_000     # лимит тела запроса на Vercel около 4.5 МБ
IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}
CAPTION_LIMIT = 1024

SCHEMA = """
create table if not exists accounts(
  id serial primary key, name text, api_id int, api_hash text, phone text,
  session text, pending_session text, pending_hash text,
  status text default 'new', blocked_until timestamptz, created_at timestamptz default now());
create table if not exists chats(
  account_id int references accounts(id) on delete cascade, chat_id bigint,
  kind text, title text, username text, primary key(account_id, chat_id));
alter table chats add column if not exists raw_id bigint;
alter table chats add column if not exists ptype text;
alter table chats add column if not exists access_hash bigint;
create table if not exists flags(chat_id bigint primary key, skip boolean default false);
create table if not exists test_recipients(id serial primary key, label text, target text);
create table if not exists media(id serial primary key, filename text, mime text, data bytea);
create table if not exists campaigns(
  id serial primary key, name text, text text, account_ids int[], kinds text[],
  max_contacts int default 0, per_minute int default 10, per_day int default 0,
  window_start int default 0, window_end int default 24, tz text default 'Europe/Moscow',
  status text default 'draft', created_at timestamptz default now());
alter table campaigns add column if not exists media_id int;
alter table campaigns add column if not exists tested_at timestamptz;
create table if not exists targets(
  id serial primary key, campaign_id int references campaigns(id) on delete cascade,
  account_id int, chat_id bigint, title text, status text default 'pending',
  error text, sent_at timestamptz);
create index if not exists targets_idx on targets(campaign_id, account_id, status);
"""
_schema_ready = False


# ---------- безопасность ----------
def secret() -> str:
    s = os.environ.get("SECRET_KEY")
    if not s:
        raise HTTPException(500, "SECRET_KEY не задан")
    return s


def fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret().encode()).digest()))


def enc(v: str) -> str:
    return fernet().encrypt(v.encode()).decode()


def dec(v: str) -> str:
    return fernet().decrypt(v.encode()).decode()


def sign(exp: int) -> str:
    return hmac.new(secret().encode(), str(exp).encode(), hashlib.sha256).hexdigest()


def auth(request: Request):
    tok = request.cookies.get(COOKIE, "")
    try:
        exp, sig = tok.split(".")
        if int(exp) > time.time() and hmac.compare_digest(sig, sign(int(exp))):
            return
    except ValueError:
        pass
    raise HTTPException(401, "Нужен вход")


async def ensure_schema(con):
    global _schema_ready
    if not _schema_ready:
        await con.execute(SCHEMA)
        _schema_ready = True


async def get_db():
    con = await asyncpg.connect(os.environ["DATABASE_URL"], statement_cache_size=0)
    try:
        await ensure_schema(con)
        yield con
    finally:
        await con.close()


@app.get("/api/health")
async def health():
    """Диагностика без секретов: какие переменные заданы и отвечает ли база."""
    res = {k: bool(os.environ.get(k)) for k in ("APP_PASSWORD", "SECRET_KEY", "CRON_SECRET", "DATABASE_URL")}
    try:
        con = await asyncpg.connect(os.environ["DATABASE_URL"], statement_cache_size=0)
        await con.execute(SCHEMA)
        await con.close()
        res["db"] = "ok"
    except Exception as e:  # noqa: BLE001
        res["db"] = f"error: {type(e).__name__}"
    return res


# ---------- вход ----------
class LoginIn(BaseModel):
    password: str


@app.post("/api/login")
async def login(b: LoginIn, response: Response):
    expected = os.environ.get("APP_PASSWORD", "")
    if not expected or not hmac.compare_digest(b.password, expected):
        await asyncio.sleep(1)
        raise HTTPException(401, "Неверный пароль")
    exp = int(time.time()) + COOKIE_TTL
    response.set_cookie(COOKIE, f"{exp}.{sign(exp)}", max_age=COOKIE_TTL,
                        httponly=True, secure=True, samesite="strict")
    return {"ok": True}


@app.post("/api/logout")
async def logout(response: Response):
    response.delete_cookie(COOKIE)
    return {"ok": True}


@app.get("/api/me", dependencies=[Depends(auth)])
async def me():
    return {"ok": True}


# ---------- Telegram ----------
def kind_of(e):
    if isinstance(e, User):
        return "user"
    if isinstance(e, Chat):
        return "group"
    if isinstance(e, Channel):
        return "channel" if e.broadcast else "supergroup"
    return "other"


def can_write(e):
    if isinstance(e, User):
        return not (e.bot or e.deleted or e.is_self or e.support)
    if isinstance(e, Chat):
        return not (e.deactivated or e.left)
    if isinstance(e, Channel):
        if e.left:
            return False
        if e.broadcast:
            return bool(e.creator or (e.admin_rights and e.admin_rights.post_messages))
        if e.creator or e.admin_rights:
            return True
        r = e.default_banned_rights
        return not (r and r.send_messages)
    return False


def peer_of(row):
    """Адресат из сохранённых в базе данных: сессия Telegram не хранит access_hash между запусками."""
    if row["ptype"] == "user":
        return InputPeerUser(row["raw_id"], row["access_hash"] or 0)
    if row["ptype"] == "channel":
        return InputPeerChannel(row["raw_id"], row["access_hash"] or 0)
    return InputPeerChat(row["raw_id"])


def client_for(acc) -> TelegramClient:
    return TelegramClient(StringSession(dec(acc["session"])), acc["api_id"], dec(acc["api_hash"]))


async def deliver(client, peer, text, media):
    """Фото с подписью (если подпись влезает в лимит Telegram) либо фото и текст отдельно."""
    if not media:
        await client.send_message(peer, text)
        return
    f = io.BytesIO(bytes(media["data"]))
    f.name = media["filename"] or "photo.jpg"
    if len(text) <= CAPTION_LIMIT:
        await client.send_file(peer, f, caption=text, force_document=False)
    else:
        await client.send_file(peer, f, force_document=False)
        if text:
            await client.send_message(peer, text)


def first_word(s: str) -> str:
    return (s or "").split(" ")[0]


class AccountIn(BaseModel):
    name: str
    api_id: int
    api_hash: str
    phone: str


class CodeIn(BaseModel):
    code: str
    password: str | None = None


@app.get("/api/accounts", dependencies=[Depends(auth)])
async def list_accounts(con=Depends(get_db)):
    rows = await con.fetch(
        "select a.id, a.name, a.phone, a.status, a.blocked_until, "
        "(select count(*) from chats c where c.account_id=a.id) as chats from accounts a order by a.id")
    return [dict(r) for r in rows]


@app.post("/api/accounts", dependencies=[Depends(auth)])
async def add_account(b: AccountIn, con=Depends(get_db)):
    client = TelegramClient(StringSession(), b.api_id, b.api_hash)
    await client.connect()
    try:
        sent = await client.send_code_request(b.phone)
        pending = client.session.save()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"Telegram: {e}")
    finally:
        await client.disconnect()
    aid = await con.fetchval(
        "insert into accounts(name, api_id, api_hash, phone, pending_session, pending_hash, status) "
        "values($1,$2,$3,$4,$5,$6,'code_sent') returning id",
        b.name, b.api_id, enc(b.api_hash), b.phone, enc(pending), sent.phone_code_hash)
    return {"id": aid}


@app.post("/api/accounts/{aid}/code", dependencies=[Depends(auth)])
async def confirm_code(aid: int, b: CodeIn, con=Depends(get_db)):
    acc = await con.fetchrow("select * from accounts where id=$1", aid)
    if not acc or not acc["pending_session"]:
        raise HTTPException(404, "Нет ожидающего входа")
    client = TelegramClient(StringSession(dec(acc["pending_session"])), acc["api_id"], dec(acc["api_hash"]))
    await client.connect()
    try:
        try:
            await client.sign_in(acc["phone"], b.code, phone_code_hash=acc["pending_hash"])
        except errors.SessionPasswordNeededError:
            if not b.password:
                raise HTTPException(400, "Нужен пароль двухфакторной защиты")
            await client.sign_in(password=b.password)
        session = client.session.save()
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"Telegram: {e}")
    finally:
        await client.disconnect()
    await con.execute(
        "update accounts set session=$2, pending_session=null, pending_hash=null, status='active' where id=$1",
        aid, enc(session))
    return {"ok": True}


@app.post("/api/accounts/{aid}/sync", dependencies=[Depends(auth)])
async def sync_chats(aid: int, con=Depends(get_db)):
    acc = await con.fetchrow("select * from accounts where id=$1 and session is not null", aid)
    if not acc:
        raise HTTPException(404, "Аккаунт не найден или не авторизован")
    rows, deadline = [], time.monotonic() + TICK_BUDGET
    async with client_for(acc) as client:
        async for d in client.iter_dialogs():
            e = d.entity
            k = kind_of(e)
            if k != "other" and can_write(e):
                ptype = "user" if isinstance(e, User) else "channel" if isinstance(e, Channel) else "chat"
                rows.append((aid, d.id, k, d.name or "", getattr(e, "username", None) or "",
                             e.id, ptype, getattr(e, "access_hash", None) or 0))
            if time.monotonic() > deadline:
                break
    await con.executemany(
        "insert into chats(account_id, chat_id, kind, title, username, raw_id, ptype, access_hash) "
        "values($1,$2,$3,$4,$5,$6,$7,$8) on conflict(account_id, chat_id) do update set "
        "kind=excluded.kind, title=excluded.title, username=excluded.username, raw_id=excluded.raw_id, "
        "ptype=excluded.ptype, access_hash=excluded.access_hash", rows)
    return {"synced": len(rows)}


@app.delete("/api/accounts/{aid}", dependencies=[Depends(auth)])
async def delete_account(aid: int, con=Depends(get_db)):
    await con.execute("delete from accounts where id=$1", aid)
    return {"ok": True}


# ---------- контакты и исключения ----------
CONTACTS_BASE = """
from chats c join accounts a on a.id=c.account_id left join flags f on f.chat_id=c.chat_id
where ($1::text is null or c.title ilike '%'||$1||'%' or c.username ilike '%'||$1||'%' or c.chat_id::text=$1)
and ($2::text is null or c.kind=$2)
and ($3::text is null or ($3='yes') = coalesce(f.skip,false))
"""


def opt(v):
    return v.strip() if v and v.strip() else None


@app.get("/api/contacts", dependencies=[Depends(auth)])
async def contacts(q: str | None = None, kind: str | None = None, excluded: str | None = None,
                   limit: int = 200, offset: int = 0, con=Depends(get_db)):
    args = (opt(q), opt(kind), opt(excluded))
    rows = await con.fetch(
        "select c.chat_id, min(c.title) as title, min(c.username) as username, min(c.kind) as kind, "
        "array_agg(distinct a.name) as accounts, coalesce(f.skip,false) as excluded "
        + CONTACTS_BASE + " group by c.chat_id, f.skip order by min(c.title) limit $4 offset $5",
        *args, min(max(limit, 1), 500), max(offset, 0))
    total = await con.fetchval("select count(distinct c.chat_id) " + CONTACTS_BASE, *args)
    return {"total": total, "items": [dict(r) for r in rows]}


class ExcludeIn(BaseModel):
    chat_ids: list[int]
    excluded: bool = True


class ExcludeFilterIn(BaseModel):
    q: str | None = None
    kind: str | None = None
    status: str | None = None     # yes / no / пусто
    excluded: bool = True


class ExcludeListIn(BaseModel):
    text: str
    excluded: bool = True


@app.post("/api/contacts/exclude", dependencies=[Depends(auth)])
async def exclude_contacts(b: ExcludeIn, con=Depends(get_db)):
    await con.executemany(
        "insert into flags(chat_id, skip) values($1,$2) on conflict(chat_id) do update set skip=excluded.skip",
        [(c, b.excluded) for c in b.chat_ids])
    return {"ok": True}


@app.post("/api/contacts/exclude-filter", dependencies=[Depends(auth)])
async def exclude_by_filter(b: ExcludeFilterIn, con=Depends(get_db)):
    res = await con.execute(
        "insert into flags(chat_id, skip) select distinct c.chat_id, $4::boolean " + CONTACTS_BASE +
        " on conflict(chat_id) do update set skip=excluded.skip",
        opt(b.q), opt(b.kind), opt(b.status), b.excluded)
    return {"changed": int(res.split()[-1])}


@app.post("/api/contacts/exclude-list", dependencies=[Depends(auth)])
async def exclude_by_list(b: ExcludeListIn, con=Depends(get_db)):
    tokens = {l.strip().lower().lstrip("@") for l in b.text.splitlines() if l.strip()}
    if not tokens:
        raise HTTPException(400, "Список пуст")
    ids = await con.fetch(
        "select distinct chat_id from chats where lower(username)=any($1) or chat_id::text=any($1)", list(tokens))
    await con.executemany(
        "insert into flags(chat_id, skip) values($1,$2) on conflict(chat_id) do update set skip=excluded.skip",
        [(r["chat_id"], b.excluded) for r in ids])
    return {"matched": len(ids), "requested": len(tokens)}


# ---------- тестовые получатели ----------
class TestRecipientIn(BaseModel):
    label: str
    target: str


@app.get("/api/test-recipients", dependencies=[Depends(auth)])
async def list_test_recipients(con=Depends(get_db)):
    return [dict(r) for r in await con.fetch("select * from test_recipients order by id")]


@app.post("/api/test-recipients", dependencies=[Depends(auth)])
async def add_test_recipient(b: TestRecipientIn, con=Depends(get_db)):
    if not b.label.strip() or not b.target.strip():
        raise HTTPException(400, "Нужны имя и @username, телефон или id")
    rid = await con.fetchval("insert into test_recipients(label, target) values($1,$2) returning id",
                             b.label.strip(), b.target.strip())
    return {"id": rid}


@app.delete("/api/test-recipients/{rid}", dependencies=[Depends(auth)])
async def delete_test_recipient(rid: int, con=Depends(get_db)):
    await con.execute("delete from test_recipients where id=$1", rid)
    return {"ok": True}


# ---------- фото ----------
@app.post("/api/media", dependencies=[Depends(auth)])
async def upload_media(file: UploadFile = File(...), con=Depends(get_db)):
    data = await file.read()
    if file.content_type not in IMAGE_TYPES:
        raise HTTPException(400, "Только фото: JPEG, PNG или WebP")
    if len(data) > MAX_IMAGE:
        raise HTTPException(400, "Фото больше 4 МБ")
    mid = await con.fetchval("insert into media(filename, mime, data) values($1,$2,$3) returning id",
                             file.filename or "photo", file.content_type, data)
    return {"id": mid}


@app.get("/api/media/{mid}", dependencies=[Depends(auth)])
async def get_media(mid: int, con=Depends(get_db)):
    row = await con.fetchrow("select mime, data from media where id=$1", mid)
    if not row:
        raise HTTPException(404, "Нет файла")
    return Response(content=bytes(row["data"]), media_type=row["mime"])


# ---------- кампании ----------
class CampaignIn(BaseModel):
    name: str
    text: str = ""
    media_id: int | None = None
    account_ids: list[int]
    kinds: list[str] = ["user", "group", "supergroup"]
    max_contacts: int = 0       # 0 = без ограничения
    per_minute: int = 10
    per_day: int = 0            # 0 = без ограничения, на аккаунт
    window_start: int = 0
    window_end: int = 24
    tz: str = "Europe/Moscow"
    exclude: str = ""           # id или @username по строке, только для этой рассылки


@app.get("/api/campaigns", dependencies=[Depends(auth)])
async def list_campaigns(con=Depends(get_db)):
    rows = await con.fetch(
        "select c.*, "
        "count(t.id) filter (where t.status='pending') as pending, "
        "count(t.id) filter (where t.status='sent') as sent, "
        "count(t.id) filter (where t.status='failed') as failed, "
        "count(t.id) filter (where t.status='skipped') as skipped "
        "from campaigns c left join targets t on t.campaign_id=c.id group by c.id order by c.id desc")
    return [dict(r) for r in rows]


@app.post("/api/campaigns", dependencies=[Depends(auth)])
async def create_campaign(b: CampaignIn, con=Depends(get_db)):
    if not b.account_ids or not (b.text.strip() or b.media_id):
        raise HTTPException(400, "Нужны текст или фото и хотя бы один аккаунт")
    if not 1 <= b.per_minute <= 20:
        raise HTTPException(400, "Сообщений в минуту: от 1 до 20")
    try:
        ZoneInfo(b.tz)
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "Неизвестный часовой пояс")
    if b.media_id and not await con.fetchval("select 1 from media where id=$1", b.media_id):
        raise HTTPException(400, "Фото не найдено, загрузите заново")
    exclude = {l.strip().lower().lstrip("@") for l in b.exclude.splitlines() if l.strip()}
    chats = await con.fetch(
        "select c.account_id, c.chat_id, c.title, c.username from chats c "
        "left join flags f on f.chat_id=c.chat_id "
        "where c.account_id=any($1) and c.kind=any($2) and not coalesce(f.skip,false) "
        "order by c.account_id, c.chat_id", b.account_ids, b.kinds)
    seen, targets = set(), []
    for c in chats:
        if c["chat_id"] in seen or str(c["chat_id"]) in exclude or c["username"].lower() in exclude:
            continue
        seen.add(c["chat_id"])
        targets.append((c["account_id"], c["chat_id"], c["title"]))
    if b.max_contacts > 0:
        targets = targets[:b.max_contacts]
    if not targets:
        raise HTTPException(400, "Нет чатов: сначала нажмите «Синхронизировать чаты» у аккаунтов")
    cid = await con.fetchval(
        "insert into campaigns(name, text, media_id, account_ids, kinds, max_contacts, per_minute, per_day, "
        "window_start, window_end, tz) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) returning id",
        b.name, b.text, b.media_id, b.account_ids, b.kinds, b.max_contacts, b.per_minute, b.per_day,
        b.window_start, b.window_end, b.tz)
    await con.executemany(
        "insert into targets(campaign_id, account_id, chat_id, title) values($1,$2,$3,$4)",
        [(cid, a, ch, t) for a, ch, t in targets])
    return {"id": cid, "targets": len(targets)}


class StatusIn(BaseModel):
    status: str


@app.post("/api/campaigns/{cid}/status", dependencies=[Depends(auth)])
async def set_status(cid: int, b: StatusIn, con=Depends(get_db)):
    if b.status not in ("running", "paused"):
        raise HTTPException(400, "running или paused")
    if b.status == "running" and not await con.fetchval("select tested_at from campaigns where id=$1", cid):
        raise HTTPException(400, "Сначала отправьте тест на тестовые аккаунты")
    await con.execute("update campaigns set status=$2 where id=$1 and status<>'done'", cid, b.status)
    return {"ok": True}


@app.post("/api/campaigns/{cid}/test", dependencies=[Depends(auth)])
async def test_campaign(cid: int, con=Depends(get_db)):
    c = await con.fetchrow("select * from campaigns where id=$1", cid)
    if not c:
        raise HTTPException(404, "Рассылка не найдена")
    recipients = await con.fetch("select * from test_recipients order by id")
    if not recipients:
        raise HTTPException(400, "Добавьте тестовых получателей на вкладке «Тест»")
    now = datetime.now(timezone.utc)
    acc = None
    for aid in c["account_ids"]:
        a = await con.fetchrow("select * from accounts where id=$1 and status='active'", aid)
        if a and not (a["blocked_until"] and a["blocked_until"] > now):
            acc = a
            break
    if not acc:
        raise HTTPException(400, "Нет доступного аккаунта для отправки теста")
    media = await con.fetchrow("select filename, data from media where id=$1", c["media_id"]) if c["media_id"] else None
    results = []
    async with client_for(acc) as client:
        for r in recipients:
            target = r["target"].strip()
            try:
                if target.lstrip("-").isdigit():
                    row = await con.fetchrow(
                        "select ptype, raw_id, access_hash from chats where account_id=$1 and chat_id=$2",
                        acc["id"], int(target))
                    peer = peer_of(row) if row else int(target)
                else:
                    peer = target
                text = c["text"].replace("{name}", first_word(r["label"]))
                await deliver(client, peer, text, media)
                results.append({"label": r["label"], "ok": True})
            except Exception as e:  # noqa: BLE001
                results.append({"label": r["label"], "ok": False, "error": type(e).__name__ + ": " + str(e)[:120]})
            await asyncio.sleep(2)
    if any(x["ok"] for x in results):
        await con.execute("update campaigns set tested_at=now() where id=$1", cid)
    return {"account": acc["name"], "results": results}


@app.delete("/api/campaigns/{cid}", dependencies=[Depends(auth)])
async def delete_campaign(cid: int, con=Depends(get_db)):
    mid = await con.fetchval("select media_id from campaigns where id=$1", cid)
    await con.execute("delete from campaigns where id=$1", cid)
    if mid and not await con.fetchval("select 1 from campaigns where media_id=$1", mid):
        await con.execute("delete from media where id=$1", mid)
    return {"ok": True}


@app.get("/api/campaigns/{cid}/targets", dependencies=[Depends(auth)])
async def campaign_targets(cid: int, status: str | None = None, con=Depends(get_db)):
    rows = await con.fetch(
        "select title, status, error, sent_at from targets where campaign_id=$1 "
        "and ($2::text is null or status=$2) order by id limit 500", cid, status)
    return [dict(r) for r in rows]


# ---------- тик по cron ----------
def in_window(c, now_utc) -> bool:
    h = now_utc.astimezone(ZoneInfo(c["tz"])).hour
    s, e = c["window_start"], c["window_end"]
    return s <= h < e if s < e else (h >= s or h < e)


async def run_account(c, aid, deadline):
    con = await asyncpg.connect(os.environ["DATABASE_URL"], statement_cache_size=0)
    try:
        acc = await con.fetchrow("select * from accounts where id=$1", aid)
        now = datetime.now(timezone.utc)
        if not acc or acc["status"] != "active" or (acc["blocked_until"] and acc["blocked_until"] > now):
            return
        n = c["per_minute"]
        if c["per_day"] > 0:
            day_start = now.astimezone(ZoneInfo(c["tz"])).replace(hour=0, minute=0, second=0, microsecond=0)
            sent_today = await con.fetchval(
                "select count(*) from targets where campaign_id=$1 and account_id=$2 "
                "and status='sent' and sent_at>=$3", c["id"], aid, day_start)
            n = min(n, c["per_day"] - sent_today)
        if n <= 0:
            return
        media = await con.fetchrow("select filename, data from media where id=$1", c["media_id"]) \
            if c["media_id"] else None
        gap = min(60 / c["per_minute"], 42 / n)
        client = client_for(acc)
        await client.connect()
        try:
            if not await client.is_user_authorized():
                await con.execute("update accounts set status='error' where id=$1", aid)
                return
            for i in range(n):
                if time.monotonic() > deadline:
                    break
                t = await con.fetchrow(
                    "update targets set status='sending' where id=(select id from targets "
                    "where campaign_id=$1 and account_id=$2 and status='pending' order by id "
                    "limit 1 for update skip locked) returning id, chat_id, title", c["id"], aid)
                if not t:
                    break
                status, err, stop = "sent", None, False
                try:
                    row = await con.fetchrow(
                        "select ptype, raw_id, access_hash from chats where account_id=$1 and chat_id=$2",
                        aid, t["chat_id"])
                    if not row or not row["ptype"]:
                        raise LookupError("PeerNotSynced")
                    text = c["text"].replace("{name}", first_word(t["title"]))
                    await deliver(client, peer_of(row), text, media)
                except errors.FloodWaitError as e:
                    status, stop = "pending", True
                    await con.execute("update accounts set blocked_until=$2 where id=$1", aid,
                                      now + timedelta(seconds=e.seconds + 5))
                except errors.PeerFloodError:
                    status, stop = "pending", True
                    await con.execute("update accounts set blocked_until=$2 where id=$1", aid,
                                      now + timedelta(hours=24))
                except Exception as e:  # noqa: BLE001
                    status, err = "failed", type(e).__name__
                await con.execute(
                    "update targets set status=$2, error=$3, sent_at=case when $2='sent' then now() end "
                    "where id=$1", t["id"], status, err)
                if stop:
                    break
                if i < n - 1:
                    await asyncio.sleep(gap * random.uniform(0.85, 1.15))
        finally:
            await client.disconnect()
    finally:
        await con.close()


@app.get("/api/tick")
@app.post("/api/tick")
async def tick(request: Request):
    cron = os.environ.get("CRON_SECRET", "")
    if not cron or not hmac.compare_digest(request.headers.get("authorization", ""), f"Bearer {cron}"):
        raise HTTPException(401, "Нет доступа")
    con = await asyncpg.connect(os.environ["DATABASE_URL"], statement_cache_size=0)
    try:
        await ensure_schema(con)
        camps = await con.fetch("select * from campaigns where status='running'")
        if camps:
            # исключённые после создания рассылки контакты пропускаем
            await con.execute(
                "update targets set status='skipped' where campaign_id=any($1) and status='pending' "
                "and chat_id in (select chat_id from flags where skip)", [c["id"] for c in camps])
        now = datetime.now(timezone.utc)
        deadline = time.monotonic() + TICK_BUDGET
        jobs = [run_account(c, aid, deadline) for c in camps if in_window(c, now) for aid in c["account_ids"]]
        await asyncio.gather(*jobs, return_exceptions=True)
        await con.execute(
            "update campaigns c set status='done' where status='running' and not exists "
            "(select 1 from targets t where t.campaign_id=c.id and t.status in ('pending','sending'))")
    finally:
        await con.close()
    return {"campaigns": len(camps)}


# ---------- интерфейс ----------
PAGE = r"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Рассылка · ServiceGuru</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Rubik:wght@500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--navy:#192853;--navy2:#143157;--purple:#5338ef;--purple2:#6f4bff;--green:#43b485;--cyan:#4fb3d3;--pink:#d73ba8;
--gold:#f1cb7f;--danger:#e85d75;--success:#1f8a5f;--warn:#8a6a1e;--bg:#f5f7fa;--panel2:#f7f8fc;--ink:#171b2e;--line:#e5e8f0;--brick:#c8385a}
*{box-sizing:border-box}
body{margin:0;font:15px/1.55 Manrope,'Segoe UI',system-ui,sans-serif;color:var(--ink);-webkit-font-smoothing:antialiased;
background:radial-gradient(60% 45% at 92% -5%,rgba(83,56,239,.14),transparent 65%),radial-gradient(50% 40% at 0% 8%,rgba(79,179,211,.14),transparent 65%),var(--bg);background-attachment:fixed}
h1,h2,h3{font-family:Rubik,'Segoe UI',sans-serif;color:var(--navy);letter-spacing:-.01em;margin:0}
h1{font-size:clamp(24px,5vw,32px)}h2{font-size:18px;margin-bottom:12px}h3{font-size:15px}
.wrap{max-width:1180px;margin:0 auto;padding:0 16px 48px}
header{position:sticky;top:0;z-index:20;background:rgba(255,255,255,.85);backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
.top{max-width:1180px;margin:0 auto;padding:10px 16px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.logo-mark{display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;border-radius:12px;color:#fff;font:800 15px Rubik,sans-serif;
background:linear-gradient(135deg,#4fb3d3 0%,#5338ef 60%,#d73ba8 100%);flex:none}.logo-mark.sm{width:30px;height:30px;font-size:12px;border-radius:10px}
.brand{display:flex;align-items:center;gap:10px;min-width:0}.brand b{font:600 17px Rubik,sans-serif;color:var(--navy);display:block;line-height:1.1}.brand small{color:rgba(23,27,46,.5);font-size:12px}
nav{display:flex;gap:4px;overflow-x:auto;flex:1;scrollbar-width:none}nav::-webkit-scrollbar{display:none}
nav button{border:0;background:none;white-space:nowrap;border-radius:999px;padding:8px 16px;font:600 14px Manrope,sans-serif;color:rgba(23,27,46,.6);cursor:pointer}
nav button:hover{background:rgba(25,40,83,.05);color:var(--navy)}nav button.on{background:rgba(83,56,239,.1);color:var(--purple)}
.card{background:#fff;border:1px solid var(--line);border-radius:18px;padding:20px;box-shadow:0 6px 18px rgba(25,40,83,.08);margin-bottom:16px}
.eyebrow{display:inline-block;border-radius:999px;padding:3px 12px;font:600 12px Manrope;text-transform:uppercase;letter-spacing:.04em;color:var(--purple);background:rgba(83,56,239,.08)}
label{display:block;font-size:13px;font-weight:600;color:rgba(23,27,46,.7);margin:12px 0 5px}
input,textarea,select{width:100%;font:inherit;color:var(--ink);background:#fff;border:1px solid var(--line);border-radius:12px;padding:10px 13px;outline:none;transition:.15s}
input:focus,textarea:focus,select:focus{border-color:var(--purple);box-shadow:0 0 0 4px rgba(83,56,239,.15)}
input[type=checkbox]{width:auto;accent-color:var(--purple)}input[type=file]{padding:8px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:0;border-radius:15px;padding:9px 16px;font:600 14px Rubik,sans-serif;color:#fff;cursor:pointer;
background:linear-gradient(135deg,#5338ef,#6f4bff);box-shadow:0 10px 24px rgba(83,56,239,.28);transition:.15s}
.btn:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 14px 30px rgba(83,56,239,.36)}
.btn:disabled{opacity:.5;cursor:not-allowed;box-shadow:none}
.btn.sec{background:#fff;color:var(--navy);border:1px solid var(--line);box-shadow:none}.btn.sec:hover:not(:disabled){border-color:var(--purple);color:var(--purple)}
.btn.dng{background:#fff;color:var(--brick);border:1px solid rgba(232,93,117,.35);box-shadow:none}
.btn.sm{padding:6px 12px;font-size:13px;border-radius:12px}
.row{display:flex;gap:12px;flex-wrap:wrap}.row>*{flex:1;min-width:140px}.row.tight>*{flex:none;min-width:0}
.item{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center;padding:12px 0;border-top:1px solid var(--line)}.item:first-of-type{border-top:0}
.btns{display:flex;gap:8px;flex-wrap:wrap}.mut{color:rgba(23,27,46,.55);font-size:13px}
.pill{display:inline-flex;align-items:center;border-radius:999px;padding:2px 10px;font:600 12px Manrope;background:rgba(25,40,83,.06);color:rgba(23,27,46,.65)}
.pill.ok{background:rgba(67,180,133,.16);color:var(--success)}.pill.warn{background:rgba(241,203,127,.35);color:var(--warn)}.pill.bad{background:rgba(232,93,117,.14);color:var(--brick)}.pill.pur{background:rgba(83,56,239,.1);color:var(--purple)}
.grid{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:20px;align-items:start}
@media(max-width:900px){.grid{grid-template-columns:1fr}.sticky{position:static!important}}
@media(max-width:700px){.top nav{order:3;flex-basis:100%}.top #out{margin-left:auto}}
.sticky{position:sticky;top:92px}
.phone{width:300px;max-width:100%;margin:0 auto;border:9px solid var(--navy);border-radius:36px;overflow:hidden;background:#cfd9e3;box-shadow:0 16px 42px rgba(25,40,83,.2)}
.ph-top{display:flex;gap:10px;align-items:center;background:#fff;padding:10px 12px;border-bottom:1px solid var(--line)}.ph-top b{display:block;font-size:14px;line-height:1.1}.ph-top small{color:#6b7480;font-size:11px}
.ph-body{min-height:300px;padding:14px 10px;background:linear-gradient(#dfe8f0,#cfdbe6)}
.msg{background:#fff;border-radius:4px 16px 16px 16px;padding:5px;max-width:92%;box-shadow:0 1px 2px rgba(0,0,0,.12);overflow:hidden}
.msg img{display:block;width:100%;border-radius:11px;margin-bottom:4px}.msg .tx{padding:3px 8px;font-size:14px;word-break:break-word}
.msg .tm{text-align:right;font-size:11px;color:#8a97a5;padding:0 8px 3px}
.contact{display:flex;gap:10px;align-items:center;padding:10px 0;border-top:1px solid var(--line)}.contact:first-child{border-top:0}
.contact .nm{flex:1;min-width:0}.contact .nm b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.modal{position:fixed;inset:0;background:rgba(25,40,83,.5);z-index:50;display:flex;align-items:center;justify-content:center;padding:16px}
.modal>div{background:#fff;border-radius:22px;padding:20px;max-width:560px;width:100%;max-height:88vh;overflow:auto}
#msg{position:fixed;top:14px;left:50%;transform:translateX(-50%);max-width:92vw;padding:11px 16px;border-radius:14px;background:var(--navy);color:#fff;display:none;z-index:99;white-space:pre-wrap;box-shadow:0 16px 42px rgba(25,40,83,.3)}#msg.bad{background:var(--danger)}
.thumb{width:44px;height:44px;border-radius:12px;object-fit:cover;border:1px solid var(--line)}
.login{max-width:420px;margin:60px auto}
</style></head><body><div id="msg"></div><div id="root"></div><script>
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function note(t,bad){const m=$('#msg');m.textContent=t;m.className=bad?'bad':'';m.style.display='block';clearTimeout(note.t);note.t=setTimeout(()=>m.style.display='none',bad?15000:6000)}
async function api(m,u,b,form){const o={method:m,headers:{}};if(form)o.body=b;else if(b!==undefined){o.headers['Content-Type']='application/json';o.body=JSON.stringify(b)}
 const r=await fetch(u,o);if(r.status==401&&u!=='/api/login'){login();throw 0}
 const d=await r.json().catch(()=>({}));
 if(!r.ok){const det=Array.isArray(d.detail)?d.detail.map(x=>x.msg).join('; '):d.detail;note(det||('Ошибка '+r.status),1);throw d}return d}
function modal(html){const m=document.createElement('div');m.className='modal';m.innerHTML='<div>'+html+'</div>';
 m.addEventListener('click',e=>{if(e.target===m)m.remove()});document.body.appendChild(m);return m}
const stMap={draft:['черновик',''],running:['идёт','ok'],paused:['пауза','warn'],done:['завершена','pur'],active:['активен','ok'],code_sent:['ждёт код','warn'],error:['ошибка','bad']};
const pill=s=>{const [t,c]=stMap[s]||[s,''];return `<span class="pill ${c}">${t}</span>`};
const kindName={user:'личный',group:'группа',supergroup:'супергруппа',channel:'канал'};

/* ---- вход ---- */
function login(){$('#root').innerHTML=`<div class="login"><div style="text-align:center;margin-bottom:24px"><span class="logo-mark" style="width:52px;height:52px;border-radius:18px;font-size:18px;box-shadow:0 14px 30px rgba(83,56,239,.32)">SG</span>
 <div style="margin:14px 0 10px"><span class="eyebrow">Рассылка</span></div><h1>Вход в панель</h1><p class="mut">ServiceGuru · рассылки по Telegram</p></div>
 <div class="card" style="padding:26px;border-radius:28px"><label style="margin-top:0">Пароль</label><input id="pw" type="password" autocomplete="current-password" autofocus>
 <button class="btn" id="go" style="width:100%;margin-top:18px;padding:12px">Войти</button></div></div>`;
 const go=async()=>{try{await api('POST','/api/login',{password:$('#pw').value})}catch{return}start()};
 $('#go').onclick=go;$('#pw').addEventListener('keydown',e=>{if(e.key==='Enter')go()})}

/* ---- каркас ---- */
const TABS=[['campaigns','Рассылки'],['contacts','Контакты'],['accounts','Аккаунты'],['tests','Тест']];
let tab=(()=>{try{return localStorage.getItem('tab')}catch{return null}})()||'campaigns';
function shell(){$('#root').innerHTML=`<header><div class="top"><div class="brand"><span class="logo-mark">SG</span><div><b>Рассылка</b><small>ServiceGuru</small></div></div>
 <nav>${TABS.map(([k,t])=>`<button data-t="${k}" class="${k===tab?'on':''}">${t}</button>`).join('')}</nav>
 <button class="btn sec sm" id="out">Выйти</button></div></header><div class="wrap"><div id="view" style="padding-top:20px"></div></div>`;
 $$('nav button').forEach(b=>b.onclick=()=>show(b.dataset.t));
 $('#out').onclick=async()=>{await api('POST','/api/logout');login()}}
async function show(t){tab=t;try{localStorage.setItem('tab',t)}catch{}
 $$('nav button').forEach(b=>b.classList.toggle('on',b.dataset.t===t));
 $('#view').innerHTML='<p class="mut">Загрузка…</p>';try{await VIEWS[t]()}catch(e){if(e!==0&&e!==undefined&&!e.detail)$('#view').innerHTML='<p class="mut">Не удалось загрузить</p>'}}
async function start(){shell();show(tab)}

/* ---- предпросмотр на телефоне ---- */
function phone(text,img,sender,name){
 const t=esc(text||'').replace(/\{name\}/g,esc(name||'Анна')).replace(/\n/g,'<br>');
 return `<div class="phone"><div class="ph-top"><span class="logo-mark sm">SG</span><div><b>${esc(sender||'ServiceGuru')}</b><small>в сети</small></div></div>
 <div class="ph-body"><div class="msg">${img?`<img src="${img}" alt="">`:''}<div class="tx" ${t?'':'style="color:#8a97a5"'}>${t||'Текст сообщения'}</div><div class="tm">12:30</div></div></div></div>`}

/* ---- рассылки ---- */
async function campaignsView(){
 const [accs,camps,tests]=await Promise.all([api('GET','/api/accounts'),api('GET','/api/campaigns'),api('GET','/api/test-recipients')]);
 const act=accs.filter(a=>a.status==='active');
 $('#view').innerHTML=`<div class="grid"><div>
 <div class="card"><h2>Рассылки</h2>${camps.map(c=>`<div class="item"><div style="display:flex;gap:12px;align-items:center;min-width:0">
  ${c.media_id?`<img class="thumb" src="/api/media/${c.media_id}">`:''}<div style="min-width:0"><b>${esc(c.name)}</b> ${pill(c.status)}
  <div class="mut">отправлено ${c.sent} · в очереди ${c.pending} · ошибок ${c.failed}${c.skipped?' · пропущено '+c.skipped:''} · ${c.per_minute}/мин · ${c.window_start}–${c.window_end} ч</div>
  ${c.tested_at?'':'<div class="mut" style="color:var(--warn)">Тест ещё не отправлялся</div>'}</div></div>
  <div class="btns"><button class="btn sec sm" onclick="prevC(${c.id})">Предпросмотр</button><button class="btn sec sm" onclick="testC(${c.id},this)">Тест</button>
  ${c.status==='running'?`<button class="btn sec sm" onclick="st(${c.id},'paused')">Пауза</button>`:c.status!=='done'?`<button class="btn sm" ${c.tested_at?'':'disabled title="Сначала отправьте тест"'} onclick="st(${c.id},'running')">Запустить</button>`:''}
  <button class="btn sec sm" onclick="tg(${c.id})">Детали</button><button class="btn dng sm" onclick="delC(${c.id})">Удалить</button></div></div>`).join('')||'<p class="mut">Пока нет рассылок</p>'}</div>
 <div class="card"><h2>Новая рассылка</h2>
 <label style="margin-top:0">Название</label><input id="cn">
 <label>Текст ({name} — первое слово названия чата)</label><textarea id="ct" rows="5"></textarea>
 <label>Фото (необязательно, JPEG/PNG/WebP до 4 МБ)</label><input id="cf" type="file" accept="image/jpeg,image/png,image/webp">
 <label>Аккаунты</label><div class="row tight">${act.map(a=>`<label style="margin:0;display:flex;gap:6px;align-items:center"><input type="checkbox" class="ca" value="${a.id}" checked> ${esc(a.name)}</label>`).join('')||'<span class="mut">Нет активных аккаунтов — добавьте на вкладке «Аккаунты»</span>'}</div>
 <label>Типы чатов</label><div class="row tight">${['user','group','supergroup','channel'].map(k=>`<label style="margin:0;display:flex;gap:6px;align-items:center"><input type="checkbox" class="ck" value="${k}" ${k!=='channel'?'checked':''}> ${kindName[k]}</label>`).join('')}</div>
 <div class="row"><div><label>Сообщений в минуту (на аккаунт)</label><input id="pm" type="number" value="10" min="1" max="20"></div>
 <div><label>Макс. в день на аккаунт (0 — без лимита)</label><input id="pd" type="number" value="0" min="0"></div>
 <div><label>Макс. контактов всего (0 — все)</label><input id="mc" type="number" value="0" min="0"></div></div>
 <div class="row"><div><label>Отправлять с (час)</label><input id="ws" type="number" value="9" min="0" max="23"></div><div><label>до (час)</label><input id="we" type="number" value="20" min="1" max="24"></div>
 <div><label>Часовой пояс</label><input id="tz" value="Europe/Moscow"></div></div>
 <label>Не писать в этой рассылке (id или @username, по строке; постоянные исключения — на вкладке «Контакты»)</label><textarea id="ex" rows="2"></textarea>
 <div class="btns" style="margin-top:16px"><button class="btn" id="cc">Создать (на паузе)</button></div>
 <p class="mut">Запуск откроется после отправки теста на тестовые аккаунты (${tests.length} в списке).</p></div></div>
 <div class="sticky"><div class="card"><h2>Как увидит получатель</h2><div id="pv"></div><label>Имя в примере</label><input id="pn" value="Анна"></div></div></div>`;
 let img=null;const upd=()=>{$('#pv').innerHTML=phone($('#ct').value,img,(act[0]||{}).name,$('#pn').value)};
 $('#ct').oninput=upd;$('#pn').oninput=upd;upd();
 $('#cf').onchange=e=>{const f=e.target.files[0];if(!f){img=null;return upd()}if(f.size>4e6){note('Фото больше 4 МБ',1);e.target.value='';img=null;return upd()}img=URL.createObjectURL(f);upd()};
 $('#cc').onclick=async()=>{const b=$('#cc');b.disabled=true;try{let media_id=null;const f=$('#cf').files[0];
  if(f){const fd=new FormData();fd.append('file',f);media_id=(await api('POST','/api/media',fd,true)).id}
  const r=await api('POST','/api/campaigns',{name:$('#cn').value||'Без названия',text:$('#ct').value,media_id,account_ids:$$('.ca:checked').map(x=>+x.value),kinds:$$('.ck:checked').map(x=>x.value),
   per_minute:+$('#pm').value,per_day:+$('#pd').value,max_contacts:+$('#mc').value,window_start:+$('#ws').value,window_end:+$('#we').value,tz:$('#tz').value,exclude:$('#ex').value});
  note('Создано, контактов: '+r.targets+'. Отправьте тест и запустите.');campaignsView()}catch{}finally{b.disabled=false}}}
async function prevC(id){const c=(await api('GET','/api/campaigns')).find(x=>x.id===id);
 modal(phone(c.text,c.media_id?'/api/media/'+c.media_id:null,'ServiceGuru','Анна')+'<div class="btns" style="margin-top:14px"><button class="btn sec" onclick="this.closest(\'.modal\').remove()">Закрыть</button></div>')}
async function testC(id,b){b.disabled=true;b.textContent='Отправка…';try{const r=await api('POST',`/api/campaigns/${id}/test`);
 modal(`<h2>Тест с аккаунта «${esc(r.account)}»</h2>${r.results.map(x=>`<div class="item"><b>${esc(x.label)}</b>${x.ok?'<span class="pill ok">доставлено</span>':`<span class="pill bad">${esc(x.error)}</span>`}</div>`).join('')}
 <div class="btns" style="margin-top:14px"><button class="btn" onclick="this.closest('.modal').remove()">Готово</button></div>`)}catch{}finally{campaignsView()}}
async function st(id,s){try{await api('POST',`/api/campaigns/${id}/status`,{status:s})}catch{}campaignsView()}
async function delC(id){if(confirm('Удалить рассылку?')){await api('DELETE','/api/campaigns/'+id);campaignsView()}}
async function tg(id){const r=await api('GET',`/api/campaigns/${id}/targets`);const L={pending:'в очереди',sending:'отправка',sent:'отправлено',failed:'ошибка',skipped:'пропущен'};const C={sent:'ok',failed:'bad',skipped:'warn'};
 modal(`<h2>Получатели (первые 500)</h2>${r.map(x=>`<div class="item"><span>${esc(x.title)}</span><span class="pill ${C[x.status]||''}">${L[x.status]||x.status}${x.error?': '+esc(x.error):''}</span></div>`).join('')||'<p class="mut">Пусто</p>'}
 <div class="btns" style="margin-top:14px"><button class="btn sec" onclick="this.closest('.modal').remove()">Закрыть</button></div>`)}

/* ---- контакты ---- */
const CF={q:'',kind:'',status:'',offset:0};
async function contactsView(){
 $('#view').innerHTML=`<div class="card"><h2>Контакты и исключения</h2>
 <p class="mut">Исключённым контактам рассылки не отправляются: ни новые, ни уже созданные. Список собирается при синхронизации чатов аккаунтов.</p>
 <div class="row"><div><label style="margin-top:0">Поиск</label><input id="fq" placeholder="название или @username" value="${esc(CF.q)}"></div>
 <div><label style="margin-top:0">Тип</label><select id="fk"><option value="">Все</option>${Object.entries(kindName).map(([k,t])=>`<option value="${k}" ${CF.kind===k?'selected':''}>${t}</option>`).join('')}</select></div>
 <div><label style="margin-top:0">Статус</label><select id="fs"><option value="">Все</option><option value="no" ${CF.status==='no'?'selected':''}>Получают рассылки</option><option value="yes" ${CF.status==='yes'?'selected':''}>Исключены</option></select></div></div>
 <div class="btns" style="margin-top:12px"><button class="btn sm" id="fa">Найти</button><button class="btn dng sm" id="fx">Исключить всех найденных</button><button class="btn sec sm" id="fr">Вернуть всех найденных</button></div>
 <div id="cl" style="margin-top:12px"></div><div id="cm"></div></div>
 <div class="card"><h2>Исключить списком</h2><p class="mut">Вставьте @username или id чатов, по одному в строке.</p>
 <textarea id="el" rows="4"></textarea><div class="btns" style="margin-top:10px"><button class="btn" id="eb">Исключить</button></div></div>`;
 const read=()=>{CF.q=$('#fq').value;CF.kind=$('#fk').value;CF.status=$('#fs').value};
 const load=async(more)=>{read();if(!more)CF.offset=0;const p=new URLSearchParams({q:CF.q,kind:CF.kind,excluded:CF.status,limit:200,offset:CF.offset});
  const r=await api('GET','/api/contacts?'+p);const html=r.items.map(c=>`<div class="contact"><div class="nm"><b>${esc(c.title||'(без названия)')}</b>
   <span class="mut">${c.username?'@'+esc(c.username)+' · ':''}${kindName[c.kind]||c.kind} · ${esc(c.accounts.join(', '))}</span></div>
   ${c.excluded?'<span class="pill bad">не писать</span>':''}<button class="btn ${c.excluded?'sec':'dng'} sm" data-id="${c.chat_id}" data-x="${c.excluded?0:1}">${c.excluded?'Вернуть':'Не писать'}</button></div>`).join('');
  if(more)$('#cl').insertAdjacentHTML('beforeend',html);else $('#cl').innerHTML=r.total?`<p class="mut">Найдено: ${r.total}</p>`+html:'<p class="mut">Ничего нет. Синхронизируйте чаты на вкладке «Аккаунты».</p>';
  CF.offset+=r.items.length;$('#cm').innerHTML=CF.offset<r.total?'<button class="btn sec sm" id="mr" style="margin-top:10px">Показать ещё</button>':'';if($('#mr'))$('#mr').onclick=()=>load(true)};
 $('#cl').addEventListener('click',async e=>{const b=e.target.closest('button[data-id]');if(!b)return;
  await api('POST','/api/contacts/exclude',{chat_ids:[+b.dataset.id],excluded:b.dataset.x==='1'});load()});
 $('#fa').onclick=()=>load();$('#fq').addEventListener('keydown',e=>{if(e.key==='Enter')load()});
 const bulk=async v=>{read();if(!confirm((v?'Исключить':'Вернуть')+' всех найденных контактов по текущему фильтру?'))return;
  const r=await api('POST','/api/contacts/exclude-filter',{q:CF.q,kind:CF.kind,status:CF.status,excluded:v});note('Изменено контактов: '+r.changed);load()};
 $('#fx').onclick=()=>bulk(true);$('#fr').onclick=()=>bulk(false);
 $('#eb').onclick=async()=>{const r=await api('POST','/api/contacts/exclude-list',{text:$('#el').value,excluded:true});note(`Исключено: ${r.matched} из ${r.requested} в списке`);$('#el').value='';load()};
 load()}

/* ---- аккаунты ---- */
async function accountsView(){const accs=await api('GET','/api/accounts');
 $('#view').innerHTML=`<div class="card"><h2>Аккаунты Telegram</h2>${accs.map(a=>`<div class="item"><div><b>${esc(a.name)}</b> ${esc(a.phone)} ${pill(a.status)}
 <div class="mut">чатов: ${a.chats}${a.blocked_until?' · пауза до '+new Date(a.blocked_until).toLocaleString('ru'):''}</div></div>
 <div class="btns">${a.status==='code_sent'?`<button class="btn sm" onclick="code(${a.id})">Ввести код</button>`:`<button class="btn sec sm" onclick="sync(${a.id},this)">Синхронизировать чаты</button>`}
 <button class="btn dng sm" onclick="delA(${a.id})">Удалить</button></div></div>`).join('')||'<p class="mut">Пока нет аккаунтов</p>'}</div>
 <div class="card"><h2>Добавить аккаунт</h2><div class="row"><div><label style="margin-top:0">Название</label><input id="an"></div><div><label style="margin-top:0">Телефон</label><input id="ap" placeholder="+7..."></div></div>
 <div class="row"><div><label>api_id</label><input id="ai" inputmode="numeric"></div><div><label>api_hash</label><input id="ah"></div></div>
 <div class="btns" style="margin-top:14px"><button class="btn" id="aa">Получить код</button></div>
 <p class="mut">api_id и api_hash берутся на <a href="https://my.telegram.org" target="_blank" rel="noopener">my.telegram.org</a> → API development tools.</p></div>`;
 $('#aa').onclick=async()=>{try{await api('POST','/api/accounts',{name:$('#an').value,phone:$('#ap').value,api_id:+$('#ai').value,api_hash:$('#ah').value});accountsView()}catch{}}}
async function code(id){const c=prompt('Код из Telegram');if(!c)return;const p=prompt('Пароль 2FA (если нет — оставьте пустым)')||null;try{await api('POST',`/api/accounts/${id}/code`,{code:c,password:p})}catch{}accountsView()}
async function sync(id,b){b.disabled=true;b.textContent='Идёт…';try{const r=await api('POST',`/api/accounts/${id}/sync`);note('Чатов: '+r.synced)}catch{}accountsView()}
async function delA(id){if(confirm('Удалить аккаунт?')){await api('DELETE','/api/accounts/'+id);accountsView()}}

/* ---- тест ---- */
async function testsView(){const t=await api('GET','/api/test-recipients');
 $('#view').innerHTML=`<div class="card"><h2>Тестовые получатели</h2><p class="mut">Тест из рассылки уходит только им. Нужно отправить хотя бы один успешный тест, прежде чем запускать рассылку. Получателей может быть сколько угодно.</p>
 ${t.map(x=>`<div class="item"><div><b>${esc(x.label)}</b> <span class="mut">${esc(x.target)}</span></div><button class="btn dng sm" onclick="delT(${x.id})">Удалить</button></div>`).join('')||'<p class="mut">Пока никого нет</p>'}</div>
 <div class="card"><h2>Добавить</h2><div class="row"><div><label style="margin-top:0">Имя (подставляется в {name})</label><input id="tl" placeholder="Например, Дмитрий"></div>
 <div><label style="margin-top:0">@username, телефон или id</label><input id="tt" placeholder="@username"></div></div>
 <div class="btns" style="margin-top:14px"><button class="btn" id="ta">Добавить</button></div>
 <p class="mut">Надёжнее всего @username. По телефону Telegram находит только тех, кто есть в контактах аккаунта-отправителя.</p></div>`;
 $('#ta').onclick=async()=>{try{await api('POST','/api/test-recipients',{label:$('#tl').value,target:$('#tt').value});testsView()}catch{}}}
async function delT(id){await api('DELETE','/api/test-recipients/'+id);testsView()}

const VIEWS={campaigns:campaignsView,contacts:contactsView,accounts:accountsView,tests:testsView};
api('GET','/api/me').then(start).catch(e=>{if(e!==0)login()});
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return PAGE
