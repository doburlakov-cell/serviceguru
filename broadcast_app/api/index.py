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


TICK_BUDGET = 55          # секунд на один тик (лимит функции 60)
SEND_BUDGET = 40          # из них на отправку рассылок; остальное — входящие, ответы, прочтение
INBOX_EVERY = 100         # не чаще раза в N секунд проверяем входящие аккаунта
NEEDS_WINDOW = timedelta(hours=24)
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
alter table campaigns add column if not exists start_at timestamptz;
alter table campaigns add column if not exists per_hour int;
alter table campaigns add column if not exists dedupe boolean default true;
alter table campaigns add column if not exists dupes int default 0;
update campaigns set per_hour = per_minute * 60 where per_hour is null;
alter table media add column if not exists created_at timestamptz default now();
create table if not exists tested(key text primary key, at timestamptz default now());
create table if not exists targets(
  id serial primary key, campaign_id int references campaigns(id) on delete cascade,
  account_id int, chat_id bigint, title text, status text default 'pending',
  error text, sent_at timestamptz);
create index if not exists targets_idx on targets(campaign_id, account_id, status);
alter table targets add column if not exists message_id bigint;
alter table targets add column if not exists read_at timestamptz;
alter table accounts add column if not exists reads_checked_at timestamptz;
create index if not exists targets_chat_idx on targets(chat_id);
alter table targets add column if not exists replied_at timestamptz;
alter table targets add column if not exists reply_checked_id bigint;
create table if not exists account_events(
  id serial primary key, account_id int, kind text, seconds int, at timestamptz default now());
alter table accounts add column if not exists inbox_checked_at timestamptz;
create table if not exists messages(
  id serial primary key, account_id int references accounts(id) on delete cascade, chat_id bigint,
  tg_id bigint, out boolean, text text, kind text default 'text', date timestamptz default now(),
  status text default 'sent', error text, campaign_id int, media_id int);
create unique index if not exists messages_uq on messages(account_id, chat_id, tg_id);
create index if not exists messages_chat_idx on messages(account_id, chat_id, date);
create table if not exists conversations(
  account_id int references accounts(id) on delete cascade, chat_id bigint,
  unread int default 0, seen_at timestamptz, needs_reply text, needs_since timestamptz, triage_at timestamptz,
  primary key(account_id, chat_id));
"""
SCHEMA_VERSION = 5   # увеличивайте при любом изменении SCHEMA
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
    """Обновляет структуру базы один раз на версию схемы. Блокировка нужна, потому что при холодном
    старте несколько запросов приходят одновременно, а параллельные ALTER TABLE приводят к deadlock."""
    global _schema_ready
    if _schema_ready:
        return
    await con.fetchval("select pg_advisory_lock(424242)")
    try:
        await con.execute("create table if not exists meta(k text primary key, v int)")
        if await con.fetchval("select v from meta where k='schema'") != SCHEMA_VERSION:
            await con.execute(SCHEMA)
            await con.execute("insert into meta(k, v) values('schema', $1) "
                              "on conflict(k) do update set v=excluded.v", SCHEMA_VERSION)
    finally:
        await con.fetchval("select pg_advisory_unlock(424242)")
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
        await ensure_schema(con)
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
    """Фото с подписью (если подпись влезает в лимит Telegram) либо фото и текст отдельно.
    Возвращает id последнего отправленного сообщения (по нему определяем прочтение)."""
    if not media:
        return (await client.send_message(peer, text)).id
    f = io.BytesIO(bytes(media["data"]))
    f.name = media["filename"] or "photo.jpg"
    if len(text) <= CAPTION_LIMIT:
        return (await client.send_file(peer, f, caption=text, force_document=False)).id
    last = await client.send_file(peer, f, force_document=False)
    if text:
        last = await client.send_message(peer, text)
    return last.id


LOCK_BASE = 7_000_000


async def lock_account(con, aid):
    """Одну сессию Telegram нельзя использовать из двух мест сразу: блокировка на время запроса."""
    if not await con.fetchval("select pg_try_advisory_lock($1)", LOCK_BASE + aid):
        raise HTTPException(409, "Аккаунт сейчас занят отправкой, повторите через минуту")


async def mark_reads(con, aid, ro):
    """ro: {chat_id: read_outbox_max_id}. Личное сообщение прочитано, если его id не больше отметки диалога."""
    rows = await con.fetch(
        "select t.id, t.chat_id, t.message_id from targets t join chats c "
        "on c.account_id=t.account_id and c.chat_id=t.chat_id "
        "where t.account_id=$1 and t.status='sent' and t.read_at is null and t.message_id is not null "
        "and c.kind='user' and t.sent_at > now() - interval '30 days'", aid)
    ids = [r["id"] for r in rows if r["message_id"] <= ro.get(r["chat_id"], 0)]
    if ids:
        await con.execute("update targets set read_at=now() where id=any($1)", ids)
    return len(ids)


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
    await lock_account(con, aid)
    rows, ro, deadline = [], {}, time.monotonic() + TICK_BUDGET
    async with client_for(acc) as client:
        async for d in client.iter_dialogs():
            e = d.entity
            k = kind_of(e)
            if k != "other" and can_write(e):
                ptype = "user" if isinstance(e, User) else "channel" if isinstance(e, Channel) else "chat"
                rows.append((aid, d.id, k, d.name or "", getattr(e, "username", None) or "",
                             e.id, ptype, getattr(e, "access_hash", None) or 0))
            if isinstance(e, User):
                ro[d.id] = d.dialog.read_outbox_max_id
            if time.monotonic() > deadline:
                break
    await con.executemany(
        "insert into chats(account_id, chat_id, kind, title, username, raw_id, ptype, access_hash) "
        "values($1,$2,$3,$4,$5,$6,$7,$8) on conflict(account_id, chat_id) do update set "
        "kind=excluded.kind, title=excluded.title, username=excluded.username, raw_id=excluded.raw_id, "
        "ptype=excluded.ptype, access_hash=excluded.access_hash", rows)
    marked = await mark_reads(con, aid, ro)
    await con.execute("update accounts set reads_checked_at=now() where id=$1", aid)
    return {"synced": len(rows), "reads": marked}


@app.delete("/api/accounts/{aid}", dependencies=[Depends(auth)])
async def delete_account(aid: int, con=Depends(get_db)):
    await con.execute("delete from accounts where id=$1", aid)
    return {"ok": True}


# ---------- контакты и исключения ----------
CONTACTS_BASE = """
from chats c join accounts a on a.id=c.account_id
left join flags f on f.chat_id=c.chat_id
left join (select chat_id, count(*) filter (where status='sent') as sent,
                  count(*) filter (where read_at is not null) as reads, max(sent_at) as last_sent
           from targets group by chat_id) s on s.chat_id=c.chat_id
where ($1::text is null or c.title ilike '%'||$1||'%' or c.username ilike '%'||$1||'%' or c.chat_id::text=$1)
and ($2::text is null or c.kind = any(case when $2='groups' then array['group','supergroup'] else array[$2::text] end))
and ($3::text is null or ($3='yes') = coalesce(f.skip,false))
and ($4::int is null or c.account_id=$4)
and ($5::int is null or coalesce(s.sent,0) >= $5)
and ($6::int is null or coalesce(s.sent,0) <= $6)
and ($7::text is null or ($7='yes' and coalesce(s.reads,0)>0)
     or ($7='no' and coalesce(s.sent,0)>0 and coalesce(s.reads,0)=0))
"""
SORTS = {"name": "min(c.title)", "sent": "coalesce(s.sent,0) desc, min(c.title)",
         "last": "s.last_sent desc nulls last, min(c.title)"}


def opt(v):
    return v.strip() if v and v.strip() else None


def contact_args(q, kind, excluded, account, sent_min, sent_max, read):
    return (opt(q), opt(kind), opt(excluded), account, sent_min, sent_max, opt(read))


@app.get("/api/contacts", dependencies=[Depends(auth)])
async def contacts(q: str | None = None, kind: str | None = None, excluded: str | None = None,
                   account: int | None = None, sent_min: int | None = None, sent_max: int | None = None,
                   read: str | None = None, sort: str = "name",
                   limit: int = 200, offset: int = 0, con=Depends(get_db)):
    args = contact_args(q, kind, excluded, account, sent_min, sent_max, read)
    rows = await con.fetch(
        "select c.chat_id, min(c.title) as title, min(c.username) as username, min(c.kind) as kind, "
        "array_agg(distinct a.name) as accounts, coalesce(f.skip,false) as excluded, "
        "coalesce(s.sent,0) as sent, coalesce(s.reads,0) as reads, s.last_sent "
        + CONTACTS_BASE + " group by c.chat_id, f.skip, s.sent, s.reads, s.last_sent order by "
        + SORTS.get(sort, SORTS["name"]) + " limit $8 offset $9",
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
    account: int | None = None
    sent_min: int | None = None
    sent_max: int | None = None
    read: str | None = None
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
    args = contact_args(b.q, b.kind, b.status, b.account, b.sent_min, b.sent_max, b.read)
    res = await con.execute(
        "insert into flags(chat_id, skip) select distinct c.chat_id, $8::boolean " + CONTACTS_BASE +
        " on conflict(chat_id) do update set skip=excluded.skip", *args, b.excluded)
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
    per_hour: int = 60          # сообщений в час на аккаунт
    per_day: int = 0            # 0 = без ограничения, на аккаунт
    window_start: int = 0
    window_end: int = 24
    tz: str = "Europe/Moscow"
    exclude: str = ""           # id или @username по строке, только для этой рассылки
    dedupe: bool = True         # дубликатор: один человек — одно сообщение с одного аккаунта
    start_at: str | None = None  # локальное время в поясе tz, например 2026-10-21T10:00


def test_key(text: str, media_id) -> str:
    return hashlib.sha256(f"{(text or '').strip()}|{media_id or ''}".encode()).hexdigest()


def parse_local(value: str, tz: str) -> datetime:
    """Время из выбора даты (без пояса) трактуется в часовом поясе рассылки."""
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        raise HTTPException(400, "Неверная дата и время")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo(tz))
    dt = dt.astimezone(timezone.utc)
    if dt < datetime.now(timezone.utc) - timedelta(minutes=2):
        raise HTTPException(400, "Это время уже прошло")
    return dt


def assign_targets(rows, dedupe):
    """rows: строки chats (account_id, chat_id, title, hist). Возвращает (цели, число убранных дублей).
    Дубликатор: человек, который есть у нескольких аккаунтов, получает одно сообщение — с аккаунта,
    где уже есть переписка с ним, иначе с наименее загруженного."""
    if not dedupe:
        return [(r["account_id"], r["chat_id"], r["title"]) for r in rows], 0
    by_chat: dict[int, list] = {}
    for r in rows:
        by_chat.setdefault(r["chat_id"], []).append(r)
    load: dict[int, int] = {}
    chosen = []
    for chat_id, cands in by_chat.items():           # сначала те, кто есть только у одного аккаунта
        if len(cands) == 1:
            r = cands[0]
            load[r["account_id"]] = load.get(r["account_id"], 0) + 1
            chosen.append((r["account_id"], chat_id, r["title"]))
    for chat_id, cands in sorted(by_chat.items()):   # затем дубли
        if len(cands) == 1:
            continue
        with_hist = [r for r in cands if r["hist"]]
        pool = with_hist or cands
        r = min(pool, key=lambda x: (load.get(x["account_id"], 0), x["account_id"]))
        load[r["account_id"]] = load.get(r["account_id"], 0) + 1
        chosen.append((r["account_id"], chat_id, r["title"]))
    chosen.sort(key=lambda t: (t[0], t[1]))
    return chosen, len(rows) - len(chosen)


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
    if not 1 <= b.per_hour <= 1200:
        raise HTTPException(400, "Сообщений в час: от 1 до 1200")
    try:
        ZoneInfo(b.tz)
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "Неизвестный часовой пояс")
    if b.media_id and not await con.fetchval("select 1 from media where id=$1", b.media_id):
        raise HTTPException(400, "Фото не найдено, загрузите заново")
    start_utc = parse_local(b.start_at, b.tz) if b.start_at else None
    tested = bool(await con.fetchval(
        "select 1 from tested where key=$1 and at > now() - interval '24 hours'", test_key(b.text, b.media_id)))
    if start_utc and not tested:
        raise HTTPException(400, "Сначала нажмите «Тест» с этим текстом и фото")
    exclude = {l.strip().lower().lstrip("@") for l in b.exclude.splitlines() if l.strip()}
    chats = await con.fetch(
        "select c.account_id, c.chat_id, c.title, c.username, "
        "exists(select 1 from messages m where m.account_id=c.account_id and m.chat_id=c.chat_id) as hist "
        "from chats c left join flags f on f.chat_id=c.chat_id "
        "where c.account_id=any($1) and c.kind=any($2) and not coalesce(f.skip,false) "
        "order by c.account_id, c.chat_id", b.account_ids, b.kinds)
    rows = [c for c in chats if str(c["chat_id"]) not in exclude and c["username"].lower() not in exclude]
    targets, dupes = assign_targets(rows, b.dedupe)
    if b.max_contacts > 0:
        targets = targets[:b.max_contacts]
    if not targets:
        raise HTTPException(400, "Нет чатов: сначала нажмите «Синхронизировать чаты» у аккаунтов")
    cid = await con.fetchval(
        "insert into campaigns(name, text, media_id, account_ids, kinds, max_contacts, per_minute, per_day, "
        "window_start, window_end, tz, status, start_at, tested_at) "
        "values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,case when $14::boolean then now() end) returning id",
        b.name, b.text, b.media_id, b.account_ids, b.kinds, b.max_contacts, max(1, -(-b.per_hour // 60)), b.per_day,
        b.window_start, b.window_end, b.tz, "scheduled" if start_utc else "draft", start_utc, tested)
    await con.execute("update campaigns set per_hour=$2, dedupe=$3, dupes=$4 where id=$1",
                      cid, b.per_hour, b.dedupe, dupes)
    await con.executemany(
        "insert into targets(campaign_id, account_id, chat_id, title) values($1,$2,$3,$4)",
        [(cid, a, ch, t) for a, ch, t in targets])
    per_account: dict[str, int] = {}
    names = {r["id"]: r["name"] for r in await con.fetch("select id, name from accounts where id=any($1)", b.account_ids)}
    for a, _, _ in targets:
        per_account[names.get(a, str(a))] = per_account.get(names.get(a, str(a)), 0) + 1
    return {"id": cid, "targets": len(targets), "dupes": dupes, "per_account": per_account}


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


async def send_test(con, account_ids, text, media_id):
    """Отправляет текст и фото всем тестовым получателям с первого доступного аккаунта."""
    recipients = await con.fetch("select * from test_recipients order by id")
    if not recipients:
        raise HTTPException(400, "Добавьте тестовых получателей на вкладке «Тест»")
    now = datetime.now(timezone.utc)
    acc = None
    for aid in account_ids:
        a = await con.fetchrow("select * from accounts where id=$1 and status='active'", aid)
        if a and not (a["blocked_until"] and a["blocked_until"] > now):
            acc = a
            break
    if not acc:
        raise HTTPException(400, "Нет доступного аккаунта для отправки теста")
    await lock_account(con, acc["id"])
    media = await con.fetchrow("select filename, data from media where id=$1", media_id) if media_id else None
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
                await deliver(client, peer, text.replace("{name}", first_word(r["label"])), media)
                results.append({"label": r["label"], "ok": True})
            except Exception as e:  # noqa: BLE001
                results.append({"label": r["label"], "ok": False, "error": type(e).__name__ + ": " + str(e)[:120]})
            await asyncio.sleep(2)
    return {"account": acc["name"], "results": results}


class TestSendIn(BaseModel):
    text: str = ""
    media_id: int | None = None
    account_ids: list[int]


@app.post("/api/test-send", dependencies=[Depends(auth)])
async def test_send(b: TestSendIn, con=Depends(get_db)):
    """Тест из формы новой рассылки: рассылка ещё не создана, успех запоминается по тексту и фото."""
    if not (b.text.strip() or b.media_id):
        raise HTTPException(400, "Нужны текст или фото")
    out = await send_test(con, b.account_ids, b.text, b.media_id)
    if any(x["ok"] for x in out["results"]):
        await con.execute(
            "insert into tested(key, at) values($1, now()) on conflict(key) do update set at=now()",
            test_key(b.text, b.media_id))
    return out


@app.post("/api/campaigns/{cid}/test", dependencies=[Depends(auth)])
async def test_campaign(cid: int, con=Depends(get_db)):
    c = await con.fetchrow("select * from campaigns where id=$1", cid)
    if not c:
        raise HTTPException(404, "Рассылка не найдена")
    out = await send_test(con, c["account_ids"], c["text"], c["media_id"])
    if any(x["ok"] for x in out["results"]):
        await con.execute("update campaigns set tested_at=now() where id=$1", cid)
    return out


class ScheduleIn(BaseModel):
    start_at: str


@app.post("/api/campaigns/{cid}/schedule", dependencies=[Depends(auth)])
async def schedule_campaign(cid: int, b: ScheduleIn, con=Depends(get_db)):
    c = await con.fetchrow("select * from campaigns where id=$1", cid)
    if not c:
        raise HTTPException(404, "Рассылка не найдена")
    if c["status"] == "done":
        raise HTTPException(400, "Рассылка уже завершена")
    if not c["tested_at"]:
        raise HTTPException(400, "Сначала отправьте тест на тестовые аккаунты")
    start_utc = parse_local(b.start_at, c["tz"])
    await con.execute("update campaigns set status='scheduled', start_at=$2 where id=$1", cid, start_utc)
    return {"start_at": start_utc.isoformat()}


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


# ---------- чат (мессенджер) ----------
def msg_kind(m) -> str:
    if getattr(m, "photo", None):
        return "photo"
    if getattr(m, "sticker", None):
        return "sticker"
    if getattr(m, "voice", None) or getattr(m, "audio", None):
        return "voice"
    if getattr(m, "video", None) or getattr(m, "video_note", None) or getattr(m, "gif", None):
        return "video"
    if getattr(m, "media", None):
        return "file"
    return "text"


async def mark_needs(con, aid, cid, inbound):
    """Входящие в течение суток после нашего сообщения из рассылки попадают в «Требуют ответа»."""
    if not inbound:
        return
    last_sent = await con.fetchval(
        "select max(sent_at) from targets where account_id=$1 and chat_id=$2 and status='sent'", aid, cid)
    if not last_sent:
        return
    fresh = [d for d in inbound if last_sent <= d <= last_sent + NEEDS_WINDOW]
    if not fresh:
        return
    newest = max(fresh)
    cur = await con.fetchrow(
        "select needs_reply, triage_at from conversations where account_id=$1 and chat_id=$2", aid, cid)
    if cur and cur["needs_reply"] in ("pending", "yes"):
        await con.execute("update conversations set needs_since=greatest(coalesce(needs_since,$3),$3) "
                          "where account_id=$1 and chat_id=$2", aid, cid, newest)
        return
    if cur and cur["triage_at"] and newest <= cur["triage_at"]:
        return   # на эти сообщения решение уже принято
    await con.execute(
        "insert into conversations(account_id, chat_id, needs_reply, needs_since) values($1,$2,'pending',$3) "
        "on conflict(account_id, chat_id) do update set needs_reply='pending', needs_since=excluded.needs_since",
        aid, cid, newest)


async def store_messages(con, aid, cid, msgs):
    rows = [(aid, cid, m.id, bool(m.out), m.message or "", msg_kind(m), m.date)
            for m in msgs if not getattr(m, "action", None)]
    if not rows:
        return 0
    await con.executemany(
        "insert into messages(account_id, chat_id, tg_id, out, text, kind, date) values($1,$2,$3,$4,$5,$6,$7) "
        "on conflict(account_id, chat_id, tg_id) do update set text=excluded.text, kind=excluded.kind", rows)
    await mark_needs(con, aid, cid, [r[6] for r in rows if not r[3]])
    return len(rows)


async def flush_outbox(con, client, acc, deadline):
    """Отправляет ответы из платформы, которые не ушли сразу из-за занятого аккаунта."""
    for m in await con.fetch(
            "select id, chat_id, text, media_id from messages where account_id=$1 and out and status='queued' "
            "order by id limit 10", acc["id"]):
        if time.monotonic() > deadline:
            break
        try:
            row = await con.fetchrow(
                "select ptype, raw_id, access_hash from chats where account_id=$1 and chat_id=$2", acc["id"], m["chat_id"])
            media = await con.fetchrow("select filename, data from media where id=$1", m["media_id"]) \
                if m["media_id"] else None
            tg_id = await deliver(client, peer_of(row), m["text"], media)
            await con.execute("update messages set status='sent', tg_id=$2, date=now() where id=$1", m["id"], tg_id)
        except Exception as e:  # noqa: BLE001
            await con.execute("update messages set status='failed', error=$2 where id=$1", m["id"], type(e).__name__)
        await asyncio.sleep(1)


async def sync_inbox(con, client, acc, deadline):
    """Подтягивает новые сообщения личных диалогов и число непрочитанных (не чаще раза в INBOX_EVERY секунд)."""
    last = acc["inbox_checked_at"]
    if last and (datetime.now(timezone.utc) - last).total_seconds() < INBOX_EVERY:
        return
    await con.execute("update accounts set inbox_checked_at=now() where id=$1", acc["id"])
    known = {r["chat_id"]: r["m"] for r in await con.fetch(
        "select chat_id, max(tg_id) as m from messages where account_id=$1 group by chat_id", acc["id"])}
    mine = {r["chat_id"] for r in await con.fetch(
        "select chat_id from chats where account_id=$1 and kind='user'", acc["id"])}
    unread, todo = [], []
    async for d in client.iter_dialogs(limit=80):
        if d.id not in mine or not isinstance(d.entity, User):
            continue
        unread.append((acc["id"], d.id, d.unread_count or 0))
        if (d.dialog.top_message or 0) > known.get(d.id, 0):
            todo.append(d)
        if time.monotonic() > deadline:
            break
    if unread:
        await con.executemany(
            "insert into conversations(account_id, chat_id, unread) values($1,$2,$3) "
            "on conflict(account_id, chat_id) do update set unread=excluded.unread", unread)
    for d in todo[:12]:
        if time.monotonic() > deadline:
            break
        try:
            msgs = await client.get_messages(d.entity, limit=30, min_id=known.get(d.id, 0))
        except Exception:  # noqa: BLE001
            continue
        await store_messages(con, acc["id"], d.id, msgs)


class ChatSendIn(BaseModel):
    text: str = ""
    media_id: int | None = None


class NeedsIn(BaseModel):
    decision: str   # yes — ответ требуется, no — не требуется


@app.get("/api/inbox/summary", dependencies=[Depends(auth)])
async def inbox_summary(con=Depends(get_db)):
    return {
        "needs": await con.fetchval("select count(*) from conversations where needs_reply in ('pending','yes')"),
        "unread": await con.fetchval("select count(*) from conversations where unread > 0"),
    }


@app.get("/api/chats", dependencies=[Depends(auth)])
async def chat_list(q: str | None = None, account: int | None = None, unread: bool = False,
                    needs: bool = False, limit: int = 100, offset: int = 0, con=Depends(get_db)):
    qq = opt(q)
    join = "left join lateral" if qq else "join lateral"   # при поиске находим и контакты без переписки
    rows = await con.fetch(f"""
        select c.account_id, c.chat_id, c.title, c.username, a.name as account,
               lm.text as last_text, lm.kind as last_kind, lm.out as last_out, lm.date as last_date,
               coalesce(v.unread,0) as unread, v.needs_reply
        from chats c join accounts a on a.id=c.account_id
        {join} (select text, kind, out, date from messages m
                where m.account_id=c.account_id and m.chat_id=c.chat_id order by date desc, id desc limit 1) lm on true
        left join conversations v on v.account_id=c.account_id and v.chat_id=c.chat_id
        where c.kind='user'
          and ($1::text is null or c.title ilike '%'||$1||'%' or c.username ilike '%'||$1||'%')
          and ($2::int is null or c.account_id=$2)
          and (not $3::boolean or coalesce(v.unread,0) > 0)
          and (not $4::boolean or v.needs_reply in ('pending','yes'))
        order by lm.date desc nulls last, c.title limit $5 offset $6""",
        qq, account, unread, needs, min(max(limit, 1), 200), max(offset, 0))
    return [dict(r) for r in rows]


@app.get("/api/chats/{aid}/{cid}/messages", dependencies=[Depends(auth)])
async def chat_messages(aid: int, cid: int, before: int | None = None, limit: int = 60, con=Depends(get_db)):
    contact = await con.fetchrow(
        "select c.title, c.username, a.name as account, v.needs_reply from chats c join accounts a on a.id=c.account_id "
        "left join conversations v on v.account_id=c.account_id and v.chat_id=c.chat_id "
        "where c.account_id=$1 and c.chat_id=$2", aid, cid)
    if not contact:
        raise HTTPException(404, "Контакт не найден")
    rows = await con.fetch(
        "select id, tg_id, out, text, kind, date, status, error, media_id from messages "
        "where account_id=$1 and chat_id=$2 and ($3::int is null or id < $3) "
        "order by date desc, id desc limit $4", aid, cid, before, min(max(limit, 1), 200))
    return {"contact": dict(contact), "items": [dict(r) for r in reversed(rows)], "more": len(rows) == min(max(limit, 1), 200)}


@app.post("/api/chats/{aid}/{cid}/sync", dependencies=[Depends(auth)])
async def chat_sync(aid: int, cid: int, con=Depends(get_db)):
    """Открытие диалога: подтягиваем последние сообщения и отмечаем прочитанным в Telegram."""
    acc = await con.fetchrow("select * from accounts where id=$1 and status='active'", aid)
    row = await con.fetchrow("select ptype, raw_id, access_hash from chats where account_id=$1 and chat_id=$2", aid, cid)
    if not acc or not row:
        raise HTTPException(404, "Диалог не найден")
    await con.execute(
        "insert into conversations(account_id, chat_id, unread, seen_at) values($1,$2,0,now()) "
        "on conflict(account_id, chat_id) do update set unread=0, seen_at=now()", aid, cid)
    if not await con.fetchval("select pg_try_advisory_lock($1)", LOCK_BASE + aid):
        return {"busy": True}       # аккаунт занят отправкой: покажем то, что есть в базе
    async with client_for(acc) as client:
        peer = peer_of(row)
        n = await store_messages(con, aid, cid, await client.get_messages(peer, limit=40))
        try:
            await client.send_read_acknowledge(peer)
        except Exception:  # noqa: BLE001
            pass
    return {"synced": n}


@app.post("/api/chats/{aid}/{cid}/send", dependencies=[Depends(auth)])
async def chat_send(aid: int, cid: int, b: ChatSendIn, con=Depends(get_db)):
    if not (b.text.strip() or b.media_id):
        raise HTTPException(400, "Напишите сообщение или приложите фото")
    acc = await con.fetchrow("select * from accounts where id=$1 and status='active'", aid)
    row = await con.fetchrow("select ptype, raw_id, access_hash from chats where account_id=$1 and chat_id=$2", aid, cid)
    if not acc or not row:
        raise HTTPException(404, "Диалог не найден")
    if b.media_id and not await con.fetchval("select 1 from media where id=$1", b.media_id):
        raise HTTPException(400, "Фото не найдено, загрузите заново")
    mid = await con.fetchval(
        "insert into messages(account_id, chat_id, out, text, kind, status, media_id) "
        "values($1,$2,true,$3,$4,'queued',$5) returning id", aid, cid, b.text.strip(),
        "photo" if b.media_id else "text", b.media_id)
    queued = True
    if await con.fetchval("select pg_try_advisory_lock($1)", LOCK_BASE + aid):
        media = await con.fetchrow("select filename, data from media where id=$1", b.media_id) if b.media_id else None
        try:
            async with client_for(acc) as client:
                tg_id = await deliver(client, peer_of(row), b.text.strip(), media)
            await con.execute("update messages set status='sent', tg_id=$2, date=now() where id=$1", mid, tg_id)
            queued = False
        except Exception as e:  # noqa: BLE001
            await con.execute("update messages set status='failed', error=$2 where id=$1", mid, type(e).__name__)
            raise HTTPException(400, f"Не удалось отправить: {type(e).__name__}")
    # ответ дан: диалог уходит из «Требуют ответа»
    await con.execute(
        "update conversations set needs_reply='done', triage_at=now() where account_id=$1 and chat_id=$2 "
        "and needs_reply in ('pending','yes')", aid, cid)
    return {"id": mid, "queued": queued}


@app.get("/api/needs", dependencies=[Depends(auth)])
async def needs_list(con=Depends(get_db)):
    items = [dict(r) for r in await con.fetch("""
        select v.account_id, v.chat_id, v.needs_reply, v.needs_since, c.title, c.username, a.name as account,
               (select cm.name from targets t join campaigns cm on cm.id=t.campaign_id
                where t.account_id=v.account_id and t.chat_id=v.chat_id and t.status='sent'
                order by t.sent_at desc limit 1) as campaign,
               (select max(t.sent_at) from targets t where t.account_id=v.account_id and t.chat_id=v.chat_id
                and t.status='sent') as mailed_at
        from conversations v join chats c on c.account_id=v.account_id and c.chat_id=v.chat_id
        join accounts a on a.id=v.account_id
        where v.needs_reply in ('pending','yes') order by v.needs_since""")]
    recent = await con.fetch("""
        select account_id, chat_id, text, kind, date from (
          select m.account_id, m.chat_id, m.text, m.kind, m.date,
                 row_number() over (partition by m.account_id, m.chat_id order by m.date desc) as rn
          from messages m join conversations v on v.account_id=m.account_id and v.chat_id=m.chat_id
          where not m.out and v.needs_reply in ('pending','yes')) q
        where rn <= 3 order by date""")
    for it in items:
        it["recent"] = [dict(r) for r in recent if r["account_id"] == it["account_id"] and r["chat_id"] == it["chat_id"]]
    return items


@app.post("/api/needs/{aid}/{cid}", dependencies=[Depends(auth)])
async def needs_decide(aid: int, cid: int, b: NeedsIn, con=Depends(get_db)):
    if b.decision not in ("yes", "no"):
        raise HTTPException(400, "yes или no")
    res = await con.execute(
        "update conversations set needs_reply=$3, triage_at=now() where account_id=$1 and chat_id=$2 "
        "and needs_reply in ('pending','yes')", aid, cid, b.decision)
    if res.endswith(" 0"):
        raise HTTPException(404, "Диалог уже обработан")
    return {"ok": True}


# ---------- аналитика ----------
AN_FROM = """
from targets t join campaigns c on c.id=t.campaign_id
left join chats ch on ch.account_id=t.account_id and ch.chat_id=t.chat_id
where ($1::timestamptz is null or coalesce(t.sent_at, c.created_at) >= $1)
and ($2::int is null or t.campaign_id=$2) and ($3::int is null or t.account_id=$3)
"""
AN_COUNTS = """
count(*) filter (where t.status='sent') as sent,
count(*) filter (where t.status='sent' and ch.kind='user') as sent_users,
count(t.read_at) as reads,
count(t.replied_at) as replies,
count(*) filter (where t.status='failed') as failed,
count(*) filter (where t.status='skipped') as skipped,
count(*) filter (where t.status in ('pending','sending')) as queued
"""
AN_MEDIANS = """
percentile_cont(0.5) within group (order by extract(epoch from (t.read_at - t.sent_at)))
  filter (where t.read_at is not null) as read_sec,
percentile_cont(0.5) within group (order by extract(epoch from (t.replied_at - t.sent_at)))
  filter (where t.replied_at is not null) as reply_sec
"""


@app.get("/api/analytics", dependencies=[Depends(auth)])
async def analytics(days: int = 30, campaign: int | None = None, account: int | None = None,
                    tz: str = "Europe/Moscow", con=Depends(get_db)):
    try:
        ZoneInfo(tz)
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "Неизвестный часовой пояс")
    since = datetime.now(timezone.utc) - timedelta(days=days) if days > 0 else None
    a = (since, campaign, account)

    async def rows(q, *extra):
        return [dict(r) for r in await con.fetch(q, *a, *extra)]

    summary = (await rows("select " + AN_COUNTS + ", " + AN_MEDIANS + " " + AN_FROM))[0]
    by_day = await rows(
        "select (t.sent_at at time zone $4)::date as day, " + AN_COUNTS + " " + AN_FROM +
        " and t.sent_at is not null group by 1 order by 1", tz)
    by_hour = await rows(
        "select extract(hour from t.sent_at at time zone $4)::int as hour, " + AN_COUNTS + " " + AN_FROM +
        " and t.sent_at is not null group by 1 order by 1", tz)
    by_campaign = await rows(
        "select c.id, c.name, c.status, count(*) as total, " + AN_COUNTS + ", " + AN_MEDIANS + " " + AN_FROM +
        " group by c.id order by c.id desc")
    by_account = await rows(
        "select a.id, a.name, a.status, a.blocked_until, " + AN_COUNTS + ", " + AN_MEDIANS + " " +
        AN_FROM.replace("from targets t", "from targets t join accounts a on a.id=t.account_id", 1) +
        " group by a.id order by a.id")
    events = {r["account_id"]: r for r in await con.fetch(
        "select account_id, count(*) filter (where kind='flood_wait') as floods, "
        "count(*) filter (where kind='peer_flood') as peer_floods from account_events "
        "where ($1::timestamptz is null or at >= $1) group by account_id", since)}
    for r in by_account:
        e = events.get(r["id"])
        r["floods"], r["peer_floods"] = (e["floods"], e["peer_floods"]) if e else (0, 0)
    by_kind = await rows(
        "select coalesce(ch.kind,'unknown') as kind, " + AN_COUNTS + " " + AN_FROM + " group by 1 order by 1")
    errs = await rows(
        "select coalesce(t.error,'—') as error, count(*) as n " + AN_FROM +
        " and t.status='failed' group by 1 order by 2 desc limit 20")
    contacts = {
        "total": await con.fetchval("select count(distinct chat_id) from chats"),
        "excluded": await con.fetchval("select count(*) from flags where skip"),
        "accounts": await con.fetchval("select count(*) from accounts"),
        "accounts_active": await con.fetchval("select count(*) from accounts where status='active'"),
        "accounts_blocked": await con.fetchval(
            "select count(*) from accounts where blocked_until > now() or status='error'"),
    }
    return {"summary": summary, "by_day": by_day, "by_hour": by_hour, "by_campaign": by_campaign,
            "by_account": by_account, "by_kind": by_kind, "errors": errs, "contacts": contacts}


# ---------- тик по cron ----------
def in_window(c, now_utc) -> bool:
    h = now_utc.astimezone(ZoneInfo(c["tz"])).hour
    s, e = c["window_start"], c["window_end"]
    return s <= h < e if s < e else (h >= s or h < e)


PACE_MINUTES = 10   # скользящее окно равномерной подачи


def pace_allow(per_hour: int) -> int:
    """Сколько сообщений можно отправить за любые PACE_MINUTES минут (за час выйдет ровно per_hour)."""
    return max(1, per_hour * PACE_MINUTES // 60)


def pace_cap(per_hour: int) -> int:
    """Не больше стольких сообщений за один тик (раз в минуту)."""
    return max(1, -(-per_hour // 60))


async def send_batch(con, client, aid, c, n, deadline, now):
    """Отправляет до n сообщений рассылки с аккаунта. Возвращает (отправлено, остановить аккаунт)."""
    media = await con.fetchrow("select filename, data from media where id=$1", c["media_id"]) \
        if c["media_id"] else None
    gap = min(20.0, 36 / max(n, 1))
    sent = 0
    for i in range(n):
        if time.monotonic() > deadline:
            break
        t = await con.fetchrow(
            "update targets set status='sending' where id=(select id from targets "
            "where campaign_id=$1 and account_id=$2 and status='pending' "
            "and (not $3::boolean or not exists (select 1 from targets x where x.campaign_id=targets.campaign_id "
            "and x.chat_id=targets.chat_id and x.id<>targets.id and x.status in ('sending','sent'))) "
            "order by id limit 1 for update skip locked) returning id, chat_id, title",
            c["id"], aid, bool(c["dedupe"]) if c["dedupe"] is not None else True)
        if not t:
            break
        status, err, stop, msg_id = "sent", None, False, None
        try:
            row = await con.fetchrow(
                "select ptype, raw_id, access_hash from chats where account_id=$1 and chat_id=$2",
                aid, t["chat_id"])
            if not row or not row["ptype"]:
                raise LookupError("PeerNotSynced")
            text = c["text"].replace("{name}", first_word(t["title"]))
            msg_id = await deliver(client, peer_of(row), text, media)
        except errors.FloodWaitError as e:
            status, stop = "pending", True
            await con.execute("update accounts set blocked_until=$2 where id=$1", aid,
                              now + timedelta(seconds=e.seconds + 5))
            await con.execute("insert into account_events(account_id, kind, seconds) values($1,'flood_wait',$2)",
                              aid, e.seconds)
        except errors.PeerFloodError:
            status, stop = "pending", True
            await con.execute("update accounts set blocked_until=$2 where id=$1", aid,
                              now + timedelta(hours=24))
            await con.execute("insert into account_events(account_id, kind, seconds) values($1,'peer_flood',86400)", aid)
        except Exception as e:  # noqa: BLE001
            status, err = "failed", type(e).__name__
        await con.execute(
            "update targets set status=$2::text, error=$3, message_id=$4, "
            "sent_at=case when $2::text='sent' then now() end where id=$1", t["id"], status, err, msg_id)
        if status == "sent":
            sent += 1
            await con.execute(
                "insert into messages(account_id, chat_id, tg_id, out, text, kind, campaign_id, media_id) "
                "values($1,$2,$3,true,$4,$5,$6,$7) on conflict(account_id, chat_id, tg_id) do nothing",
                aid, t["chat_id"], msg_id, text, "photo" if media else "text", c["id"], c["media_id"])
        if stop:
            return sent, True
        if i < n - 1:
            await asyncio.sleep(gap * random.uniform(0.85, 1.15))
    return sent, False


async def refresh_reads(con, client, acc, deadline):
    """Раз в 10 минут сверяет с диалогами: прочитано ли сообщение и ответил ли человек (только личные чаты)."""
    last = acc["reads_checked_at"]
    if last and datetime.now(timezone.utc) - last < timedelta(minutes=10):
        return
    rows = await con.fetch(
        "select t.id, t.chat_id, t.message_id, t.read_at, t.replied_at, t.reply_checked_id "
        "from targets t join chats c on c.account_id=t.account_id and c.chat_id=t.chat_id "
        "where t.account_id=$1 and t.status='sent' and (t.read_at is null or t.replied_at is null) "
        "and t.message_id is not null and c.kind='user' and t.sent_at > now() - interval '30 days'", acc["id"])
    await con.execute("update accounts set reads_checked_at=now() where id=$1", acc["id"])
    if not rows:
        return
    want = {r["chat_id"] for r in rows}
    ro, top, ent = {}, {}, {}
    async for d in client.iter_dialogs():
        if d.id in want and isinstance(d.entity, User):
            ro[d.id], top[d.id], ent[d.id] = d.dialog.read_outbox_max_id, d.dialog.top_message, d.entity
        if time.monotonic() > deadline:
            break
    read_ids, replies, checked, calls = [], {}, [], 0
    for r in rows:
        cid, mid = r["chat_id"], r["message_id"]
        if r["read_at"] is None and mid <= ro.get(cid, 0):
            read_ids.append(r["id"])
        newest = top.get(cid, 0)
        # ответ ищем только если в диалоге появилось что-то новее нашего сообщения и мы это ещё не проверяли
        if r["replied_at"] is None and newest > mid and newest != r["reply_checked_id"] \
                and calls < 30 and time.monotonic() < deadline:
            calls += 1
            try:
                msgs = await client.get_messages(ent[cid], min_id=mid, limit=20)
            except Exception:  # noqa: BLE001
                continue
            inbound = [m.date for m in msgs if not m.out]
            if inbound:
                replies[r["id"]] = min(inbound)
            else:
                checked.append((r["id"], newest))
    if read_ids:
        await con.execute("update targets set read_at=now() where id=any($1)", read_ids)
    for tid, when in replies.items():
        await con.execute("update targets set replied_at=$2, read_at=coalesce(read_at, $2) where id=$1", tid, when)
    if checked:
        await con.executemany("update targets set reply_checked_id=$2 where id=$1", checked)


async def run_account(aid, camps, send_deadline, deadline):
    """Одно задание на аккаунт: рассылки по очереди (общий лимит в минуту), ответы из платформы,
    новые входящие и проверка прочтения."""
    con = await asyncpg.connect(os.environ["DATABASE_URL"], statement_cache_size=0)
    try:
        if not await con.fetchval("select pg_try_advisory_lock($1)", LOCK_BASE + aid):
            return
        acc = await con.fetchrow("select * from accounts where id=$1", aid)
        now = datetime.now(timezone.utc)
        if not acc or acc["status"] != "active":
            return
        blocked = bool(acc["blocked_until"] and acc["blocked_until"] > now)
        client = client_for(acc)
        await client.connect()
        try:
            if not await client.is_user_authorized():
                await con.execute("update accounts set status='error' where id=$1", aid)
                return
            if not blocked:
                left = 0
                if camps:
                    top = max(c["per_hour"] for c in camps)
                    recent = await con.fetchval(
                        "select count(*) from targets where account_id=$1 and status='sent' "
                        "and sent_at > now() - make_interval(mins => $2)", aid, PACE_MINUTES)
                    left = min(pace_cap(top), pace_allow(top) - recent)
                for c in camps:
                    if left <= 0:
                        break
                    recent_c = await con.fetchval(
                        "select count(*) from targets where campaign_id=$1 and account_id=$2 and status='sent' "
                        "and sent_at > now() - make_interval(mins => $3)", c["id"], aid, PACE_MINUTES)
                    n = min(pace_cap(c["per_hour"]), pace_allow(c["per_hour"]) - recent_c, left)
                    if c["per_day"] > 0:
                        day_start = now.astimezone(ZoneInfo(c["tz"])).replace(hour=0, minute=0, second=0, microsecond=0)
                        sent_today = await con.fetchval(
                            "select count(*) from targets where campaign_id=$1 and account_id=$2 "
                            "and status='sent' and sent_at>=$3", c["id"], aid, day_start)
                        n = min(n, c["per_day"] - sent_today)
                    if n <= 0:
                        continue
                    sent, stop = await send_batch(con, client, aid, c, n, send_deadline, now)
                    left -= sent
                    if stop:
                        blocked = True
                        break
                if not blocked:
                    await flush_outbox(con, client, acc, deadline)
            await sync_inbox(con, client, acc, deadline)
            await refresh_reads(con, client, acc, deadline)
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
        await con.execute("update campaigns set status='running' where status='scheduled' and start_at <= now()")
        await con.execute(
            "delete from media where created_at < now() - interval '1 day' "
            "and id not in (select media_id from campaigns where media_id is not null) "
            "and id not in (select media_id from messages where media_id is not null)")
        camps = await con.fetch("select * from campaigns where status='running' order by id")
        if camps:
            # исключённые после создания рассылки контакты пропускаем
            await con.execute(
                "update targets set status='skipped' where campaign_id=any($1) and status='pending' "
                "and chat_id in (select chat_id from flags where skip)", [c["id"] for c in camps])
        now = datetime.now(timezone.utc)
        start = time.monotonic()
        by_acc: dict[int, list] = {}
        for c in camps:
            if in_window(c, now):
                for aid in c["account_ids"]:
                    by_acc.setdefault(aid, []).append(c)
        for r in await con.fetch("select id from accounts where status='active'"):
            by_acc.setdefault(r["id"], [])   # входящие и ответы обрабатываем у всех активных аккаунтов
        await asyncio.gather(*[run_account(aid, cs, start + SEND_BUDGET, start + TICK_BUDGET)
                               for aid, cs in by_acc.items()], return_exceptions=True)
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
.grid{display:grid;grid-template-columns:minmax(0,1fr) 450px;gap:20px;align-items:start}
@media(max-width:1000px){.grid{grid-template-columns:1fr}.sticky{position:static!important}}
@media(max-width:700px){.top nav{order:3;flex-basis:100%}.top #out{margin-left:auto}}
.sticky{position:sticky;top:92px}
.pfit{position:relative;width:100%}
.phone{position:absolute;top:0;left:0;width:410px;height:864px;transform-origin:top left;border:10px solid #0f1730;border-radius:56px;overflow:hidden;
background:#fff;box-shadow:0 16px 42px rgba(25,40,83,.25);font-family:-apple-system,'Segoe UI',Roboto,sans-serif}
.screen{display:flex;flex-direction:column;height:100%}
.sbar{display:flex;justify-content:space-between;align-items:center;padding:12px 26px 6px;background:#fff;font-size:15px;font-weight:600}
.ph-top{display:flex;gap:10px;align-items:center;background:#fff;padding:6px 14px 10px;border-bottom:1px solid var(--line)}
.ph-top .back{font-size:30px;line-height:1;color:#2a8ee0;margin-right:2px}.ph-top b{display:block;font-size:16px;line-height:1.15}.ph-top small{color:#8a97a5;font-size:12.5px}
.ph-top .logo-mark.sm{width:38px;height:38px;font-size:14px}
.ph-body{flex:1;padding:12px 10px;overflow:hidden;background:linear-gradient(160deg,#dbe7d5,#c9dcc9 40%,#cfd9ea)}
.ph-body .day{width:max-content;margin:0 auto 10px;background:rgba(0,0,0,.28);color:#fff;border-radius:12px;padding:2px 10px;font-size:13px}
.msg{background:#fff;border-radius:6px 18px 18px 18px;padding:4px;max-width:82%;box-shadow:0 1px 2px rgba(0,0,0,.14);overflow:hidden}
.msg img{display:block;width:100%;max-height:340px;object-fit:cover;border-radius:14px}
.msg .tx{padding:6px 9px 2px;font-size:16px;line-height:1.35;word-break:break-word}
.msg .tm{text-align:right;font-size:12px;color:#8a97a5;padding:0 8px 3px}
.ph-in{display:flex;align-items:center;gap:12px;background:#fff;border-top:1px solid var(--line);padding:10px 14px 22px;color:#8a97a5;font-size:22px}
.ph-in .inp{flex:1;background:#f1f3f5;border-radius:20px;padding:7px 14px;font-size:16px}
.contact{display:flex;gap:10px;align-items:center;padding:10px 0;border-top:1px solid var(--line)}.contact:first-child{border-top:0}
.contact .nm{flex:1;min-width:0}.contact .nm b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.modal{position:fixed;inset:0;background:rgba(25,40,83,.5);z-index:50;display:flex;align-items:center;justify-content:center;padding:16px}
.modal>div{background:#fff;border-radius:22px;padding:20px;max-width:560px;width:100%;max-height:88vh;overflow:auto}
#msg{position:fixed;top:14px;left:50%;transform:translateX(-50%);max-width:92vw;padding:11px 16px;border-radius:14px;background:var(--navy);color:#fff;display:none;z-index:99;white-space:pre-wrap;box-shadow:0 16px 42px rgba(25,40,83,.3)}#msg.bad{background:var(--danger)}
.thumb{width:44px;height:44px;border-radius:12px;object-fit:cover;border:1px solid var(--line)}
.login{max-width:420px;margin:60px auto}
nav .cnt{display:inline-block;min-width:18px;margin-left:6px;padding:0 6px;border-radius:999px;background:var(--danger);color:#fff;font:700 11px/18px Manrope}
.msgr{display:grid;grid-template-columns:360px minmax(0,1fr);gap:20px;align-items:start}
.mlist{margin:0;padding:14px}.clist{margin-top:10px;max-height:calc(100vh - 290px);overflow-y:auto}
.chk{display:flex;gap:6px;align-items:center;margin:0;white-space:nowrap}
.citem{display:flex;gap:10px;padding:10px 6px;border-radius:14px;cursor:pointer;align-items:center}.citem:hover{background:var(--panel2)}.citem.on{background:rgba(83,56,239,.08)}
.avatar{flex:none;width:44px;height:44px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;font:700 15px Rubik,sans-serif;
background:linear-gradient(135deg,#4fb3d3,#5338ef 60%,#d73ba8)}
.cmain{flex:1;min-width:0}.cmain b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.cmain>span{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px;color:rgba(23,27,46,.55)}
.cside{text-align:right;flex:none;font-size:12px;color:rgba(23,27,46,.5)}
.badge{display:inline-block;min-width:20px;padding:0 6px;border-radius:999px;background:var(--purple);color:#fff;font:700 12px/20px Manrope;margin-top:3px}
.device{display:flex;flex-direction:column;height:calc(100vh - 150px);min-height:520px;max-height:860px;border:10px solid #0f1730;border-radius:44px;overflow:hidden;background:#fff;box-shadow:0 16px 42px rgba(25,40,83,.25)}
.dev-top{display:flex;gap:12px;align-items:center;padding:12px 16px;border-bottom:1px solid var(--line);background:#fff}
.dev-top .avatar{width:40px;height:40px;font-size:14px}.dev-name b{display:block;line-height:1.15}.dev-name small{color:#8a97a5}
.dev-top .back{display:none;border:0;background:none;font-size:32px;line-height:1;color:#2a8ee0;cursor:pointer;padding:0 6px}
.dev-body{flex:1;overflow-y:auto;padding:12px 14px;background:linear-gradient(160deg,#dbe7d5,#c9dcc9 40%,#cfd9ea)}
.dev-body .day{width:max-content;margin:10px auto;background:rgba(0,0,0,.28);color:#fff;border-radius:12px;padding:2px 10px;font-size:13px}
.b{max-width:78%;width:fit-content;margin:4px 0;padding:6px 10px 3px;border-radius:6px 18px 18px 18px;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.14);word-break:break-word;font-size:15.5px}
.b.out{margin-left:auto;background:#e4dcff;border-radius:18px 6px 18px 18px}.b .kl{font-weight:600;color:var(--purple)}
.b .tm{text-align:right;font-size:11.5px;color:#8a97a5;margin-top:1px}
.dev-in{display:flex;gap:10px;align-items:flex-end;padding:10px 14px 16px;border-top:1px solid var(--line);background:#fff}
.dev-in textarea{flex:1;border-radius:20px;padding:9px 14px;resize:none;max-height:120px;background:#f1f3f5;border:0}
.dev-in .att{cursor:pointer;font-size:22px;padding-bottom:4px}.dev-in .send{flex:none;width:42px;height:42px;border-radius:50%;border:0;color:#fff;font-size:18px;cursor:pointer;background:linear-gradient(135deg,#5338ef,#6f4bff)}
.empty{margin:auto;color:#8a97a5;text-align:center;padding:30px}
.need .recent{display:flex;flex-direction:column;gap:4px;margin:10px 0}.need .b{max-width:100%;margin:0}
@media(max-width:900px){.msgr{grid-template-columns:1fr}.msgr.has-chat .mlist{display:none}.msgr:not(.has-chat) .mchat{display:none}
 .dev-top .back{display:block}.device{height:calc(100vh - 130px);border-width:6px;border-radius:30px}.clist{max-height:none}}
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.kpi{background:#fff;border:1px solid var(--line);border-radius:18px;padding:14px 16px;box-shadow:0 6px 18px rgba(25,40,83,.08)}
.kpi small{display:block;color:rgba(23,27,46,.55);font-size:12.5px;font-weight:600}.kpi b{display:block;font:700 28px Rubik,sans-serif;color:var(--navy);line-height:1.2}
.kpi i{font-style:normal;color:rgba(23,27,46,.55);font-size:12.5px}
.bars{display:flex;gap:4px;overflow-x:auto;padding-bottom:4px}.bcol{flex:1;min-width:18px;text-align:center}
.bgrp{display:flex;align-items:flex-end;gap:2px;height:130px;border-bottom:1px solid var(--line)}.bgrp span{flex:1;border-radius:4px 4px 0 0;min-height:0}
.bcol small{display:block;font-size:10.5px;color:rgba(23,27,46,.5);white-space:nowrap}
.legend{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:10px;font-size:13px}.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px}
.tblw{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13.5px}th,td{padding:8px 10px;text-align:right;border-top:1px solid var(--line);white-space:nowrap}
th:first-child,td:first-child{text-align:left}th{font:600 12px Manrope;color:rgba(23,27,46,.55);text-transform:uppercase;letter-spacing:.03em;border-top:0}
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
const stMap={draft:['черновик',''],running:['идёт','ok'],scheduled:['запланирована','pur'],paused:['пауза','warn'],done:['завершена','pur'],active:['активен','ok'],code_sent:['ждёт код','warn'],error:['ошибка','bad']};
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
const TABS=[['campaigns','Рассылки'],['chat','Чат'],['needs','Требуют ответа'],['contacts','Контакты'],['analytics','Аналитика'],['accounts','Аккаунты'],['tests','Тест']];
let tab=(()=>{try{return localStorage.getItem('tab')}catch{return null}})()||'campaigns';
function shell(){$('#root').innerHTML=`<header><div class="top"><div class="brand"><span class="logo-mark">SG</span><div><b>Рассылка</b><small>ServiceGuru</small></div></div>
 <nav>${TABS.map(([k,t])=>`<button data-t="${k}" class="${k===tab?'on':''}">${t}</button>`).join('')}</nav>
 <button class="btn sec sm" id="out">Выйти</button></div></header><div class="wrap"><div id="view" style="padding-top:20px"></div></div>`;
 $$('nav button').forEach(b=>b.onclick=()=>show(b.dataset.t));
 $('#out').onclick=async()=>{await api('POST','/api/logout');login()}}
async function show(t){clearTimers();tab=t;try{localStorage.setItem('tab',t)}catch{}
 $$('nav button').forEach(b=>b.classList.toggle('on',b.dataset.t===t));
 $('#view').innerHTML='<p class="mut">Загрузка…</p>';try{await VIEWS[t]()}catch(e){if(e!==0&&e!==undefined&&!e.detail)$('#view').innerHTML='<p class="mut">Не удалось загрузить</p>'}}
async function refreshBadges(){try{const s=await api('GET','/api/inbox/summary');
 const set=(t,n,label)=>{const b=document.querySelector(`nav button[data-t=${t}]`);if(b)b.innerHTML=label+(n?`<span class="cnt">${n}</span>`:'')};
 set('chat',s.unread,'Чат');set('needs',s.needs,'Требуют ответа')}catch{}}
let BADGE_T=null;
async function start(){shell();show(tab);refreshBadges();clearInterval(BADGE_T);BADGE_T=setInterval(refreshBadges,60000)}

/* ---- предпросмотр на телефоне ---- */
function phone(text,img,sender,name){
 const t=esc(text||'').replace(/\{name\}/g,esc(name||'Анна')).replace(/\n/g,'<br>');
 return `<div class="pfit"><div class="phone"><div class="screen"><div class="sbar"><span>9:41</span><span style="letter-spacing:2px;font-size:13px">▂▄▆ ▮▮▮</span></div>
 <div class="ph-top"><span class="back">‹</span><span class="logo-mark sm">SG</span><div><b>${esc(sender||'ServiceGuru')}</b><small>был(а) недавно</small></div></div>
 <div class="ph-body"><div class="day">Сегодня</div><div class="msg">${img?`<img src="${img}" alt="">`:''}<div class="tx" ${t?'':'style="color:#8a97a5"'}>${t||'Текст сообщения'}</div><div class="tm">12:30</div></div></div>
 <div class="ph-in"><span>📎</span><span class="inp">Сообщение</span><span>🎤</span></div></div></div></div>`}
function fitPhones(){$$('.pfit').forEach(w=>{const ph=w.firstElementChild,k=Math.min(1,w.clientWidth/410,(innerHeight-130)/864);
 ph.style.transform=`scale(${k})`;ph.style.left=Math.max(0,(w.clientWidth-410*k)/2)+'px';w.style.height=(864*k)+'px'})}
addEventListener('resize',fitPhones);

/* ---- рассылки ---- */
async function campaignsView(){
 const [accs,camps,tests]=await Promise.all([api('GET','/api/accounts'),api('GET','/api/campaigns'),api('GET','/api/test-recipients')]);
 const act=accs.filter(a=>a.status==='active');
 $('#view').innerHTML=`<div class="grid"><div>
 <div class="card"><h2>Рассылки</h2>${camps.map(c=>`<div class="item"><div style="display:flex;gap:12px;align-items:center;min-width:0">
  ${c.media_id?`<img class="thumb" src="/api/media/${c.media_id}">`:''}<div style="min-width:0"><b>${esc(c.name)}</b> ${pill(c.status)}
  <div class="mut">отправлено ${c.sent} · в очереди ${c.pending} · ошибок ${c.failed}${c.skipped?' · пропущено '+c.skipped:''}${c.dupes?' · дублей убрано '+c.dupes:''} · ${c.per_hour||c.per_minute*60}/час · ${c.window_start}–${c.window_end} ч</div>
  ${c.status==='scheduled'&&c.start_at?`<div class="mut" style="color:var(--purple)">Старт: ${new Date(c.start_at).toLocaleString('ru',{timeZone:c.tz,dateStyle:'short',timeStyle:'short'})} (${esc(c.tz)})</div>`:''}
  ${c.tested_at?'':'<div class="mut" style="color:var(--warn)">Тест ещё не отправлялся</div>'}</div></div>
  <div class="btns"><button class="btn sec sm" onclick="prevC(${c.id})">Предпросмотр</button><button class="btn sec sm" onclick="testC(${c.id},this)">Тест</button>
  ${c.status==='running'?`<button class="btn sec sm" onclick="st(${c.id},'paused')">Пауза</button>`
   :c.status==='scheduled'?`<button class="btn sec sm" onclick="st(${c.id},'paused')">Отменить запуск</button>`
   :c.status!=='done'?`<button class="btn sm" ${c.tested_at?'':'disabled title="Сначала отправьте тест"'} onclick="st(${c.id},'running')">Запустить</button><button class="btn sec sm" ${c.tested_at?'':'disabled title="Сначала отправьте тест"'} onclick="schedC(${c.id},'${esc(c.tz)}')">Запланировать</button>`:''}
  <button class="btn sec sm" onclick="tg(${c.id})">Детали</button><button class="btn dng sm" onclick="delC(${c.id})">Удалить</button></div></div>`).join('')||'<p class="mut">Пока нет рассылок</p>'}</div>
 <div class="card"><h2>Новая рассылка</h2>
 <label style="margin-top:0">Название</label><input id="cn">
 <label>Текст ({name} — первое слово названия чата)</label><textarea id="ct" rows="5"></textarea>
 <label>Фото (необязательно, JPEG/PNG/WebP до 4 МБ)</label><input id="cf" type="file" accept="image/jpeg,image/png,image/webp">
 <label>Аккаунты</label><div class="row tight">${act.map(a=>`<label style="margin:0;display:flex;gap:6px;align-items:center"><input type="checkbox" class="ca" value="${a.id}" checked> ${esc(a.name)}</label>`).join('')||'<span class="mut">Нет активных аккаунтов — добавьте на вкладке «Аккаунты»</span>'}</div>
 <label class="chk" style="margin-top:10px" title="Если человек есть сразу у нескольких выбранных аккаунтов, сообщение уйдёт только с одного"><input type="checkbox" id="dd" checked> Дубликатор: одному человеку одно сообщение, даже если он есть у нескольких аккаунтов</label>
 <label>Типы чатов</label><div class="row tight">${['user','group','supergroup','channel'].map(k=>`<label style="margin:0;display:flex;gap:6px;align-items:center"><input type="checkbox" class="ck" value="${k}" ${k!=='channel'?'checked':''}> ${kindName[k]}</label>`).join('')}</div>
 <div class="row"><div><label>Сообщений в час (на аккаунт; безопаснее 30–60)</label><input id="pm" type="number" value="60" min="1" max="1200"></div>
 <div><label>Макс. в день на аккаунт (0 — без лимита)</label><input id="pd" type="number" value="0" min="0"></div>
 <div><label>Макс. контактов всего (0 — все)</label><input id="mc" type="number" value="0" min="0"></div></div>
 <div class="row"><div><label>Отправлять с (час)</label><input id="ws" type="number" value="9" min="0" max="23"></div><div><label>до (час)</label><input id="we" type="number" value="20" min="1" max="24"></div>
 <div><label>Часовой пояс</label><input id="tz" value="Europe/Moscow"></div></div>
 <label>Не писать в этой рассылке (id или @username, по строке; постоянные исключения — на вкладке «Контакты»)</label><textarea id="ex" rows="2"></textarea>
 <div class="btns" style="margin-top:16px"><button class="btn sec" id="ct2">Тест</button><button class="btn" id="cc">Создать (на паузе)</button><button class="btn sec" id="cs">Запланировать рассылку</button></div>
 <p class="mut">«Тест» отправляет это сообщение тестовым получателям (${tests.length} в списке, вкладка «Тест»). Запуск и планирование открываются после успешного теста.</p></div></div>
 <div class="sticky"><div class="card"><h2>Как увидит получатель</h2><div id="pv"></div><label>Имя в примере</label><input id="pn" value="Анна"></div></div></div>`;
 let img=null;const upd=()=>{$('#pv').innerHTML=phone($('#ct').value,img,(act[0]||{}).name,$('#pn').value);fitPhones()};
 $('#ct').oninput=upd;$('#pn').oninput=upd;upd();
 $('#cf').onchange=e=>{const f=e.target.files[0];if(!f){img=null;return upd()}if(f.size>4e6){note('Фото больше 4 МБ',1);e.target.value='';img=null;return upd()}img=URL.createObjectURL(f);upd()};
 let up=null;
 const ensureMedia=async()=>{const f=$('#cf').files[0];if(!f)return null;const sig=f.name+f.size+f.lastModified;if(up&&up.sig===sig)return up.id;
  const fd=new FormData();fd.append('file',f);const id=(await api('POST','/api/media',fd,true)).id;up={sig,id};return id};
 const accIds=()=>$$('.ca:checked').map(x=>+x.value);
 const body=async extra=>({name:$('#cn').value||'Без названия',text:$('#ct').value,media_id:await ensureMedia(),account_ids:accIds(),kinds:$$('.ck:checked').map(x=>x.value),
  per_hour:+$('#pm').value,per_day:+$('#pd').value,max_contacts:+$('#mc').value,window_start:+$('#ws').value,window_end:+$('#we').value,tz:$('#tz').value,exclude:$('#ex').value,dedupe:$('#dd').checked,...extra});
 $('#ct2').onclick=async()=>{const b=$('#ct2');b.disabled=true;b.textContent='Отправка…';try{
  const r=await api('POST','/api/test-send',{text:$('#ct').value,media_id:await ensureMedia(),account_ids:accIds()});showTest(r)}catch{}finally{b.disabled=false;b.textContent='Тест'}};
 $('#cc').onclick=async()=>{const b=$('#cc');b.disabled=true;try{const r=await api('POST','/api/campaigns',await body());
  note(dupeNote('Создано',r)+' Отправьте тест и запустите.');campaignsView()}catch{}finally{b.disabled=false}};
 $('#cs').onclick=()=>pickTime($('#tz').value,async when=>{const r=await api('POST','/api/campaigns',await body({start_at:when}));
  note(dupeNote('Запланировано',r));campaignsView()})}
function pickTime(tz,cb){const pad=n=>String(n).padStart(2,'0');const d=new Date(Date.now()+3600e3);
 const def=`${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:00`;
 const m=modal(`<h2>Запланировать рассылку</h2><label style="margin-top:0">Дата и время запуска</label><input type="datetime-local" id="sd" value="${def}">
  <p class="mut">Время указывается по часовому поясу рассылки: ${esc(tz)}. После старта сообщения отправляются в заданное окно часов и с заданной скоростью.</p>
  <div class="btns"><button class="btn" id="sok">Запланировать</button><button class="btn sec" onclick="this.closest('.modal').remove()">Отмена</button></div>`);
 $('#sok').onclick=async()=>{const v=$('#sd').value;if(!v){note('Выберите дату и время',1);return}const b=$('#sok');b.disabled=true;try{await cb(v);m.remove()}catch{b.disabled=false}}}
function schedC(id,tz){pickTime(tz,async when=>{await api('POST',`/api/campaigns/${id}/schedule`,{start_at:when});note('Запуск запланирован');campaignsView()})}
function showTest(r){modal(`<h2>Тест с аккаунта «${esc(r.account)}»</h2>${r.results.map(x=>`<div class="item"><b>${esc(x.label)}</b>${x.ok?'<span class="pill ok">доставлено</span>':`<span class="pill bad">${esc(x.error)}</span>`}</div>`).join('')}
 <div class="btns" style="margin-top:14px"><button class="btn" onclick="this.closest('.modal').remove()">Готово</button></div>`)}
function dupeNote(w,r){const pa=Object.entries(r.per_account||{});
 return `${w}: контактов ${r.targets}${r.dupes?`, убрано дублей ${r.dupes}`:''}${pa.length>1?` (${pa.map(([k,v])=>k+' — '+v).join(', ')})`:''}.`}
async function prevC(id){const c=(await api('GET','/api/campaigns')).find(x=>x.id===id);
 modal(phone(c.text,c.media_id?'/api/media/'+c.media_id:null,'ServiceGuru','Анна')+'<div class="btns" style="margin-top:14px"><button class="btn sec" onclick="this.closest(\'.modal\').remove()">Закрыть</button></div>');fitPhones()}
async function testC(id,b){b.disabled=true;b.textContent='Отправка…';try{showTest(await api('POST',`/api/campaigns/${id}/test`))}catch{}finally{campaignsView()}}
async function st(id,s){try{await api('POST',`/api/campaigns/${id}/status`,{status:s})}catch{}campaignsView()}
async function delC(id){if(confirm('Удалить рассылку?')){await api('DELETE','/api/campaigns/'+id);campaignsView()}}
async function tg(id){const r=await api('GET',`/api/campaigns/${id}/targets`);const L={pending:'в очереди',sending:'отправка',sent:'отправлено',failed:'ошибка',skipped:'пропущен'};const C={sent:'ok',failed:'bad',skipped:'warn'};
 modal(`<h2>Получатели (первые 500)</h2>${r.map(x=>`<div class="item"><span>${esc(x.title)}</span><span class="pill ${C[x.status]||''}">${L[x.status]||x.status}${x.error?': '+esc(x.error):''}</span></div>`).join('')||'<p class="mut">Пусто</p>'}
 <div class="btns" style="margin-top:14px"><button class="btn sec" onclick="this.closest('.modal').remove()">Закрыть</button></div>`)}

/* ---- контакты ---- */
const CF={q:'',kind:'',status:'',account:'',smin:'',smax:'',read:'',sort:'name',offset:0};
async function contactsView(){
 const accs=await api('GET','/api/accounts');
 const sel=(id,label,opts,cur)=>`<div><label style="margin-top:0">${label}</label><select id="${id}">${opts.map(([v,t])=>`<option value="${v}" ${String(cur)===String(v)?'selected':''}>${t}</option>`).join('')}</select></div>`;
 $('#view').innerHTML=`<div class="card"><h2>Контакты и исключения</h2>
 <p class="mut">Исключённым контактам рассылки не отправляются: ни новые, ни уже созданные. Список и статусы прочтения обновляются при синхронизации чатов аккаунта; прочтение отслеживается только в личных чатах (в группах и каналах Telegram его не показывает).</p>
 <div class="row"><div><label style="margin-top:0">Поиск</label><input id="fq" placeholder="название или @username" value="${esc(CF.q)}"></div>
 ${sel('fk','Тип',[['','Все'],['user','Личные'],['groups','Группы'],['channel','Каналы']],CF.kind)}
 ${sel('fa2','Из какого Telegram',[['','Все аккаунты'],...accs.map(a=>[a.id,a.name])],CF.account)}</div>
 <div class="row">${sel('fs','Статус',[['','Все'],['no','Получают рассылки'],['yes','Исключены']],CF.status)}
 <div><label style="margin-top:0">Рассылок получено: от</label><input id="fsm" type="number" min="0" value="${esc(CF.smin)}" placeholder="0"></div>
 <div><label style="margin-top:0">до</label><input id="fsx" type="number" min="0" value="${esc(CF.smax)}" placeholder="любое"></div>
 ${sel('fr','Прочитано',[['','Все'],['yes','Прочитали хотя бы одну'],['no','Писали, но не читали']],CF.read)}
 ${sel('fo','Сортировка',[['name','По названию'],['sent','По числу рассылок'],['last','По дате последней']],CF.sort)}</div>
 <div class="btns" style="margin-top:12px"><button class="btn sm" id="fa">Найти</button><button class="btn dng sm" id="fx">Исключить всех найденных</button><button class="btn sec sm" id="fr2">Вернуть всех найденных</button><button class="btn sec sm" id="f0">Сбросить фильтры</button></div>
 <div id="cl" style="margin-top:12px"></div><div id="cm"></div></div>
 <div class="card"><h2>Исключить списком</h2><p class="mut">Вставьте @username или id чатов, по одному в строке.</p>
 <textarea id="el" rows="4"></textarea><div class="btns" style="margin-top:10px"><button class="btn" id="eb">Исключить</button></div></div>`;
 const read=()=>{CF.q=$('#fq').value;CF.kind=$('#fk').value;CF.account=$('#fa2').value;CF.status=$('#fs').value;CF.smin=$('#fsm').value;CF.smax=$('#fsx').value;CF.read=$('#fr').value;CF.sort=$('#fo').value};
 const params=extra=>{const p=new URLSearchParams();[['q',CF.q],['kind',CF.kind],['account',CF.account],['excluded',CF.status],['sent_min',CF.smin],['sent_max',CF.smax],['read',CF.read]].forEach(([k,v])=>{if(v!==''&&v!=null)p.set(k,v)});
  Object.entries(extra||{}).forEach(([k,v])=>p.set(k,v));return p};
 const num=v=>v===''?null:+v;
 const stats=c=>{const parts=[`Рассылок: ${c.sent}`];parts.push(c.kind==='user'?`прочитано: ${c.reads}`:'прочтение: нет данных');
  if(c.last_sent)parts.push('последняя '+new Date(c.last_sent).toLocaleDateString('ru'));return parts.join(' · ')};
 const load=async(more)=>{read();if(!more)CF.offset=0;const r=await api('GET','/api/contacts?'+params({sort:CF.sort,limit:200,offset:CF.offset}));
  const html=r.items.map(c=>`<div class="contact"><div class="nm"><b>${esc(c.title||'(без названия)')}</b>
   <span class="mut">${c.username?'@'+esc(c.username)+' · ':''}${kindName[c.kind]||c.kind} · ${esc(c.accounts.join(', '))}</span>
   <span class="mut" style="display:block">${stats(c)}</span></div>
   ${c.excluded?'<span class="pill bad">не писать</span>':''}<button class="btn ${c.excluded?'sec':'dng'} sm" data-id="${c.chat_id}" data-x="${c.excluded?0:1}">${c.excluded?'Вернуть':'Не писать'}</button></div>`).join('');
  if(more)$('#cl').insertAdjacentHTML('beforeend',html);else $('#cl').innerHTML=r.total?`<p class="mut">Найдено: ${r.total}</p>`+html:'<p class="mut">Ничего нет. Измените фильтры или синхронизируйте чаты на вкладке «Аккаунты».</p>';
  CF.offset+=r.items.length;$('#cm').innerHTML=CF.offset<r.total?'<button class="btn sec sm" id="mr" style="margin-top:10px">Показать ещё</button>':'';if($('#mr'))$('#mr').onclick=()=>load(true)};
 $('#cl').addEventListener('click',async e=>{const b=e.target.closest('button[data-id]');if(!b)return;
  await api('POST','/api/contacts/exclude',{chat_ids:[+b.dataset.id],excluded:b.dataset.x==='1'});load()});
 $('#fa').onclick=()=>load();$('#fq').addEventListener('keydown',e=>{if(e.key==='Enter')load()});
 ['fk','fa2','fs','fr','fo'].forEach(id=>$('#'+id).addEventListener('change',()=>load()));
 $('#f0').onclick=()=>{Object.assign(CF,{q:'',kind:'',status:'',account:'',smin:'',smax:'',read:'',sort:'name'});contactsView()};
 const bulk=async v=>{read();if(!confirm((v?'Исключить':'Вернуть')+' всех найденных контактов по текущим фильтрам?'))return;
  const r=await api('POST','/api/contacts/exclude-filter',{q:CF.q||null,kind:CF.kind||null,status:CF.status||null,account:num(CF.account),sent_min:num(CF.smin),sent_max:num(CF.smax),read:CF.read||null,excluded:v});note('Изменено контактов: '+r.changed);load()};
 $('#fx').onclick=()=>bulk(true);$('#fr2').onclick=()=>bulk(false);
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
async function sync(id,b){b.disabled=true;b.textContent='Идёт…';try{const r=await api('POST',`/api/accounts/${id}/sync`);note('Чатов: '+r.synced+(r.reads?', новых прочтений: '+r.reads:''))}catch{}accountsView()}
async function delA(id){if(confirm('Удалить аккаунт?')){await api('DELETE','/api/accounts/'+id);accountsView()}}

/* ---- чат ---- */
let TIMERS=[];const clearTimers=()=>{TIMERS.forEach(clearInterval);TIMERS=[]};
let OPEN=null;const CH={q:'',account:'',unread:false};
const ini=s=>(s||'?').trim().split(/\s+/).slice(0,2).map(w=>w[0]).join('').toUpperCase()||'?';
const hhmm=d=>new Date(d).toLocaleTimeString('ru',{hour:'2-digit',minute:'2-digit'});
const dayLabel=d=>{const x=new Date(d),t=new Date(),y=new Date(Date.now()-864e5);return x.toDateString()===t.toDateString()?'Сегодня':x.toDateString()===y.toDateString()?'Вчера':x.toLocaleDateString('ru',{day:'numeric',month:'long'})};
const KL={photo:'📷 Фото',video:'🎬 Видео',voice:'🎤 Голосовое',file:'📎 Файл',sticker:'Стикер'};
const prev=(t,k)=>t||KL[k]||'';
const listTime=d=>{if(!d)return '';const x=new Date(d);return x.toDateString()===new Date().toDateString()?hhmm(d):x.toLocaleDateString('ru',{day:'2-digit',month:'2-digit'})};
function renderMsgs(items){let last='';return items.map(m=>{const day=dayLabel(m.date),sep=day!==last?`<div class="day">${day}</div>`:'';last=day;
 const st=m.out?(m.status==='queued'?'🕓':m.status==='failed'?'❗':'✓'):'';
 return sep+`<div class="b ${m.out?'out':'in'}">${m.kind&&m.kind!=='text'?`<div class="kl">${KL[m.kind]||''}</div>`:''}${m.text?`<div>${esc(m.text).replace(/\n/g,'<br>')}</div>`:''}<div class="tm">${hhmm(m.date)} ${st}${m.status==='failed'?' не отправлено':''}</div></div>`}).join('')}
async function chatView(){
 const accs=await api('GET','/api/accounts');
 $('#view').innerHTML=`<div class="msgr ${OPEN?'has-chat':''}" id="msgr"><div class="card mlist">
  <input id="cq" placeholder="Поиск по имени или @username" value="${esc(CH.q)}">
  <div class="row" style="margin-top:8px;align-items:center"><select id="ca2"><option value="">Все аккаунты</option>${accs.map(a=>`<option value="${a.id}" ${String(CH.account)===String(a.id)?'selected':''}>${esc(a.name)}</option>`).join('')}</select>
  <label class="chk"><input type="checkbox" id="cu" ${CH.unread?'checked':''}> Непрочитанные</label></div><div class="clist" id="cl2"></div></div>
  <div class="mchat"><div class="device" id="dev"></div></div></div>`;
 const loadList=async()=>{CH.q=$('#cq').value;CH.account=$('#ca2').value;CH.unread=$('#cu').checked;
  const p=new URLSearchParams({q:CH.q,unread:CH.unread});if(CH.account)p.set('account',CH.account);
  const items=await api('GET','/api/chats?'+p);
  $('#cl2').innerHTML=items.map(c=>`<div class="citem ${OPEN&&OPEN.aid==c.account_id&&OPEN.cid==c.chat_id?'on':''}" data-a="${c.account_id}" data-c="${c.chat_id}">
   <span class="avatar">${esc(ini(c.title))}</span><div class="cmain"><b>${esc(c.title||'(без имени)')}</b><span>${c.last_out?'Вы: ':''}${esc(prev(c.last_text,c.last_kind))||'нет сообщений'}</span><span><span class="pill">${esc(c.account)}</span>${c.needs_reply?' <span class="pill warn">нужен ответ</span>':''}</span></div>
   <div class="cside">${listTime(c.last_date)}${c.unread?`<br><span class="badge">${c.unread}</span>`:''}</div></div>`).join('')||'<p class="mut">Диалогов пока нет. Они появятся после рассылки или синхронизации чатов.</p>'};
 const showEmpty=()=>{$('#dev').innerHTML='<div class="empty">Выберите диалог слева</div>'};
 const loadMsgs=async(stick)=>{if(!OPEN)return;const r=await api('GET',`/api/chats/${OPEN.aid}/${OPEN.cid}/messages`);const mb=$('#mb');if(!mb)return;
  const near=mb.scrollHeight-mb.scrollTop-mb.clientHeight<80;mb.innerHTML=renderMsgs(r.items)||'<div class="empty">Сообщений пока нет</div>';if(stick||near)mb.scrollTop=mb.scrollHeight};
 const syncOpen=async()=>{if(!OPEN)return;try{await api('POST',`/api/chats/${OPEN.aid}/${OPEN.cid}/sync`)}catch{};await loadMsgs();loadList();refreshBadges()};
 const open=async(aid,cid)=>{OPEN={aid,cid};$('#msgr').classList.add('has-chat');
  const r=await api('GET',`/api/chats/${aid}/${cid}/messages`);const c=r.contact;
  $('#dev').innerHTML=`<div class="dev-top"><button class="back" id="cb">‹</button><span class="avatar">${esc(ini(c.title))}</span><div class="dev-name"><b>${esc(c.title)}</b><small>${c.username?'@'+esc(c.username)+' · ':''}${esc(c.account)}</small></div></div>
   <div class="dev-body" id="mb"></div><div class="dev-in"><label class="att" title="Фото">📎<input type="file" id="mf" accept="image/jpeg,image/png,image/webp" hidden></label>
   <textarea id="mt" rows="1" placeholder="Сообщение"></textarea><button class="send" id="ms">➤</button></div>`;
  $('#mb').innerHTML=renderMsgs(r.items)||'<div class="empty">Сообщений пока нет</div>';$('#mb').scrollTop=$('#mb').scrollHeight;
  $('#cb').onclick=()=>{OPEN=null;$('#msgr').classList.remove('has-chat');showEmpty();loadList()};
  const send=async()=>{const t=$('#mt').value.trim(),f=$('#mf').files[0];if(!t&&!f)return;const b=$('#ms');b.disabled=true;
   try{let media_id=null;if(f){const fd=new FormData();fd.append('file',f);media_id=(await api('POST','/api/media',fd,true)).id}
    const o=await api('POST',`/api/chats/${aid}/${cid}/send`,{text:t,media_id});$('#mt').value='';$('#mf').value='';if(o.queued)note('Аккаунт занят рассылкой — ответ уйдёт в течение минуты');
    await loadMsgs(true);loadList();refreshBadges()}catch{}finally{b.disabled=false}};
  $('#ms').onclick=send;$('#mt').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send()}});
  $('#mf').onchange=e=>{if(e.target.files[0])note('Фото прикреплено: '+e.target.files[0].name)};
  syncOpen()};
 showEmpty();
 $('#cl2').addEventListener('click',e=>{const it=e.target.closest('.citem');if(it)open(+it.dataset.a,+it.dataset.c).then(loadList)});
 let qt;$('#cq').addEventListener('input',()=>{clearTimeout(qt);qt=setTimeout(loadList,300)});$('#ca2').onchange=loadList;$('#cu').onchange=loadList;
 await loadList();if(OPEN)await open(OPEN.aid,OPEN.cid);
 TIMERS.push(setInterval(loadList,30000),setInterval(syncOpen,30000))}

/* ---- требуют ответа ---- */
function ago(d){if(!d)return '';const m=Math.round((Date.now()-new Date(d))/60000);return m<60?m+' мин назад':m<1440?Math.round(m/60)+' ч назад':Math.round(m/1440)+' дн назад'}
async function needsView(){const r=await api('GET','/api/needs');
 $('#view').innerHTML=`<div class="card"><h2>Требуют ответа</h2><p class="mut" style="margin:0">Ответы на рассылку, пришедшие в течение суток после отправки. Решите по каждому: если ответ нужен — откроется чат, и после вашего сообщения диалог уйдёт отсюда; если не нужен — пропадёт сразу.</p></div>`+
 (r.map(n=>`<div class="card need" id="n-${n.account_id}-${n.chat_id}"><div class="item" style="border:0;padding:0"><div style="display:flex;gap:12px;align-items:center;min-width:0"><span class="avatar">${esc(ini(n.title))}</span>
  <div><b>${esc(n.title)}</b> <span class="pill">${esc(n.account)}</span> ${n.needs_reply==='yes'?'<span class="pill pur">в работе</span>':'<span class="pill warn">новый ответ</span>'}
  <div class="mut">${n.campaign?`Рассылка «${esc(n.campaign)}», отправлена ${ago(n.mailed_at)}`:''}${n.needs_since?` · ответ ${ago(n.needs_since)}`:''}</div></div></div></div>
  <div class="recent">${n.recent.map(m=>`<div class="b in"><div>${esc(prev(m.text,m.kind)).replace(/\n/g,'<br>')}</div><div class="tm">${hhmm(m.date)}</div></div>`).join('')}</div>
  <div class="btns">${n.needs_reply==='yes'?`<button class="btn" onclick="needGo(${n.account_id},${n.chat_id})">Открыть чат</button>`:`<button class="btn" onclick="needDecide(${n.account_id},${n.chat_id},'yes')">Ответ требуется</button>`}
  <button class="btn sec" onclick="needDecide(${n.account_id},${n.chat_id},'no')">Ответ не требуется</button></div></div>`).join('')||'<div class="card"><p class="mut" style="margin:0">Пока нет ответов, требующих решения</p></div>')}
function needGo(aid,cid){OPEN={aid,cid};show('chat')}
async function needDecide(aid,cid,dec){try{await api('POST',`/api/needs/${aid}/${cid}`,{decision:dec})}catch{return needsView()}
 if(dec==='yes')return needGo(aid,cid);
 const el=document.getElementById(`n-${aid}-${cid}`);if(el)el.remove();refreshBadges();if(!document.querySelector('.need'))needsView()}

/* ---- аналитика ---- */
const AF={days:'30',campaign:'',account:''};
const pc=(a,b)=>b?(Math.round(a/b*1000)/10)+'%':'—';
const dur=s=>{if(s==null)return '—';s=+s;return s<60?Math.round(s)+' сек':s<3600?Math.round(s/60)+' мин':s<86400?(Math.round(s/360)/10)+' ч':(Math.round(s/8640)/10)+' дн'};
const ERR={PeerNotSynced:'Чат не синхронизирован',ChatWriteForbiddenError:'Нет права писать в чат',UserIsBlockedError:'Пользователь заблокировал аккаунт',UserPrivacyRestrictedError:'Настройки приватности запрещают писать',
 InputUserDeactivatedError:'Аккаунт получателя удалён',PeerIdInvalidError:'Неверный адрес получателя',ChatAdminRequiredError:'Нужны права администратора',UserBannedInChannelError:'Аккаунт забанен в чате',
 SlowModeWaitError:'В чате включён медленный режим',MessageTooLongError:'Слишком длинный текст',MediaEmptyError:'Не удалось отправить фото',ValueError:'Не найден получатель',TimeoutError:'Нет ответа от Telegram'};
const KIND_RU={user:'Личные',group:'Группы',supergroup:'Супергруппы',channel:'Каналы',unknown:'Неизвестно'};
function barChart(items,labelOf,tipOf){const max=Math.max(1,...items.map(i=>i.sent));
 return `<div class="bars">${items.map(i=>`<div class="bcol" title="${esc(tipOf(i))}"><div class="bgrp"><span style="height:${i.sent/max*100}%;background:var(--purple)"></span><span style="height:${i.reads/max*100}%;background:var(--cyan)"></span><span style="height:${i.replies/max*100}%;background:var(--green)"></span></div><small>${labelOf(i)}</small></div>`).join('')}</div>`}
async function analyticsView(){
 const [accs,camps]=await Promise.all([api('GET','/api/accounts'),api('GET','/api/campaigns')]);
 const p=new URLSearchParams({days:AF.days});if(AF.campaign)p.set('campaign',AF.campaign);if(AF.account)p.set('account',AF.account);
 const d=await api('GET','/api/analytics?'+p);const s=d.summary,c=d.contacts;
 const sel=(id,label,opts,cur)=>`<div><label style="margin-top:0">${label}</label><select id="${id}">${opts.map(([v,t])=>`<option value="${v}" ${String(cur)===String(v)?'selected':''}>${esc(t)}</option>`).join('')}</select></div>`;
 const byDay={};d.by_day.forEach(r=>byDay[r.day]=r);const days=[];
 const n=AF.days==='0'?Math.min(90,Math.max(7,d.by_day.length?Math.round((Date.now()-new Date(d.by_day[0].day))/864e5)+1:7)):Math.min(+AF.days,90);
 for(let i=n-1;i>=0;i--){const k=new Date(Date.now()-i*864e5).toLocaleDateString('sv-SE',{timeZone:'Europe/Moscow'});days.push(byDay[k]||{day:k,sent:0,reads:0,replies:0})}
 const hours=[...Array(24).keys()].map(h=>d.by_hour.find(r=>r.hour===h)||{hour:h,sent:0,reads:0,replies:0});
 const kpi=(t,v,sub)=>`<div class="kpi"><small>${t}</small><b>${v}</b><i>${sub||'&nbsp;'}</i></div>`;
 const attempts=s.sent+s.failed;
 $('#view').innerHTML=`<div class="card"><h2>Аналитика</h2><div class="row">
  ${sel('an-d','Период',[['7','7 дней'],['30','30 дней'],['90','90 дней'],['0','За всё время']],AF.days)}
  ${sel('an-c','Рассылка',[['','Все рассылки'],...camps.map(x=>[x.id,x.name])],AF.campaign)}
  ${sel('an-a','Аккаунт',[['','Все аккаунты'],...accs.map(x=>[x.id,x.name])],AF.account)}</div>
  <p class="mut" style="margin-bottom:0">«Доставлено» — сообщения, принятые Telegram (отдельного подтверждения доставки Telegram не присылает). Прочтение и ответы определяются только в личных чатах и обновляются раз в ~10 минут, поэтому время до прочтения приблизительное.</p></div>
 <div class="kpis">
  ${kpi('Доставлено',s.sent,'сообщений')}
  ${kpi('Прочитано',s.reads,pc(s.reads,s.sent_users)+' от личных')}
  ${kpi('Ответили',s.replies,pc(s.replies,s.sent_users)+' от личных')}
  ${kpi('Ошибки',s.failed,pc(s.failed,attempts)+' от попыток')}
  ${kpi('В очереди',s.queued,'ждут отправки')}
  ${kpi('Пропущено',s.skipped,'исключены из рассылки')}
  ${kpi('До прочтения',dur(s.read_sec),'медиана')}
  ${kpi('До ответа',dur(s.reply_sec),'медиана')}
  ${kpi('Контактов в базе',c.total,c.excluded+' исключено')}
  ${kpi('Аккаунтов',c.accounts,c.accounts_active+' активны · '+c.accounts_blocked+' на паузе/с ошибкой')}</div>
 <div class="card"><h2>По дням</h2><div class="legend"><span><i style="background:var(--purple)"></i>Доставлено</span><span><i style="background:var(--cyan)"></i>Прочитано</span><span><i style="background:var(--green)"></i>Ответили</span></div>
  ${barChart(days,i=>i.day.slice(8)+'.'+i.day.slice(5,7),i=>`${i.day}: доставлено ${i.sent}, прочитано ${i.reads}, ответили ${i.replies}`)}</div>
 <div class="card"><h2>По часам отправки</h2><p class="mut">В какой час отправки чаще читают и отвечают (часовой пояс Москвы).</p>
  ${barChart(hours,i=>i.hour,i=>`${i.hour}:00 — доставлено ${i.sent}, прочитано ${i.reads}, ответили ${i.replies}`)}</div>
 <div class="card"><h2>По рассылкам</h2><div class="tblw"><table><tr><th>Рассылка</th><th>Статус</th><th>Получателей</th><th>Доставлено</th><th>Прочитано</th><th>Ответили</th><th>Ошибки</th><th>Пропущено</th><th>В очереди</th><th>До прочтения</th><th>До ответа</th></tr>
  ${d.by_campaign.map(r=>`<tr><td>${esc(r.name)}</td><td>${(stMap[r.status]||[r.status])[0]}</td><td>${r.total}</td><td>${r.sent}</td><td>${r.reads} <span class="mut">${pc(r.reads,r.sent_users)}</span></td><td>${r.replies} <span class="mut">${pc(r.replies,r.sent_users)}</span></td><td>${r.failed}</td><td>${r.skipped}</td><td>${r.queued}</td><td>${dur(r.read_sec)}</td><td>${dur(r.reply_sec)}</td></tr>`).join('')||'<tr><td colspan="11" class="mut">Данных пока нет</td></tr>'}</table></div></div>
 <div class="card"><h2>По аккаунтам</h2><div class="tblw"><table><tr><th>Аккаунт</th><th>Статус</th><th>Доставлено</th><th>Прочитано</th><th>Ответили</th><th>Ошибки</th><th>Пауз Telegram</th><th>Блокировок на 24 ч</th></tr>
  ${d.by_account.map(r=>`<tr><td>${esc(r.name)}</td><td>${(stMap[r.status]||[r.status])[0]}${r.blocked_until&&new Date(r.blocked_until)>new Date()?' · пауза до '+new Date(r.blocked_until).toLocaleString('ru'):''}</td><td>${r.sent}</td><td>${r.reads} <span class="mut">${pc(r.reads,r.sent_users)}</span></td><td>${r.replies} <span class="mut">${pc(r.replies,r.sent_users)}</span></td><td>${r.failed}</td><td>${r.floods}</td><td>${r.peer_floods}</td></tr>`).join('')||'<tr><td colspan="8" class="mut">Данных пока нет</td></tr>'}</table></div></div>
 <div class="card"><h2>По типам чатов</h2><div class="tblw"><table><tr><th>Тип</th><th>Доставлено</th><th>Прочитано</th><th>Ответили</th><th>Ошибки</th><th>Пропущено</th></tr>
  ${d.by_kind.map(r=>`<tr><td>${KIND_RU[r.kind]||r.kind}</td><td>${r.sent}</td><td>${r.kind==='user'?r.reads:'—'}</td><td>${r.kind==='user'?r.replies:'—'}</td><td>${r.failed}</td><td>${r.skipped}</td></tr>`).join('')||'<tr><td colspan="6" class="mut">Данных пока нет</td></tr>'}</table></div></div>
 <div class="card"><h2>Ошибки</h2><div class="tblw"><table><tr><th>Причина</th><th>Код</th><th>Сколько</th></tr>
  ${d.errors.map(r=>`<tr><td>${esc(ERR[r.error]||'Другая ошибка')}</td><td class="mut">${esc(r.error)}</td><td>${r.n}</td></tr>`).join('')||'<tr><td colspan="3" class="mut">Ошибок нет</td></tr>'}</table></div></div>`;
 const re=()=>{AF.days=$('#an-d').value;AF.campaign=$('#an-c').value;AF.account=$('#an-a').value;analyticsView()};
 ['an-d','an-c','an-a'].forEach(id=>$('#'+id).addEventListener('change',re))}

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

const VIEWS={campaigns:campaignsView,chat:chatView,needs:needsView,contacts:contactsView,analytics:analyticsView,accounts:accountsView,tests:testsView};
api('GET','/api/me').then(start).catch(e=>{if(e!==0)login()});
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return PAGE
