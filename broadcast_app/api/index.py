"""Платформа рассылки по Telegram-аккаунтам: вход по паролю, аккаунты, кампании, тик по cron.

Окружение: APP_PASSWORD, SECRET_KEY, CRON_SECRET, DATABASE_URL (Postgres, например Neon).
"""
import asyncio
import base64
import hashlib
import hmac
import os
import random
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import asyncpg
from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from telethon import TelegramClient, errors
from telethon.sessions import StringSession
from telethon.tl.types import Channel, Chat, User

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

SCHEMA = """
create table if not exists accounts(
  id serial primary key, name text, api_id int, api_hash text, phone text,
  session text, pending_session text, pending_hash text,
  status text default 'new', blocked_until timestamptz, created_at timestamptz default now());
create table if not exists chats(
  account_id int references accounts(id) on delete cascade, chat_id bigint,
  kind text, title text, username text, primary key(account_id, chat_id));
create table if not exists campaigns(
  id serial primary key, name text, text text, account_ids int[], kinds text[],
  max_contacts int default 0, per_minute int default 10, per_day int default 0,
  window_start int default 0, window_end int default 24, tz text default 'Europe/Moscow',
  status text default 'draft', created_at timestamptz default now());
create table if not exists targets(
  id serial primary key, campaign_id int references campaigns(id) on delete cascade,
  account_id int, chat_id bigint, title text, status text default 'pending',
  error text, sent_at timestamptz);
create index if not exists targets_idx on targets(campaign_id, account_id, status);
"""


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


async def get_db():
    con = await asyncpg.connect(os.environ["DATABASE_URL"], statement_cache_size=0)
    try:
        await con.execute(SCHEMA)
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


def client_for(acc) -> TelegramClient:
    return TelegramClient(StringSession(dec(acc["session"])), acc["api_id"], dec(acc["api_hash"]))


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
            if kind_of(e) != "other" and can_write(e):
                rows.append((aid, d.id, kind_of(e), d.name or "", getattr(e, "username", None) or ""))
            if time.monotonic() > deadline:
                break
    await con.executemany(
        "insert into chats(account_id, chat_id, kind, title, username) values($1,$2,$3,$4,$5) "
        "on conflict(account_id, chat_id) do update set kind=excluded.kind, title=excluded.title, "
        "username=excluded.username", rows)
    return {"synced": len(rows)}


@app.delete("/api/accounts/{aid}", dependencies=[Depends(auth)])
async def delete_account(aid: int, con=Depends(get_db)):
    await con.execute("delete from accounts where id=$1", aid)
    return {"ok": True}


# ---------- кампании ----------
class CampaignIn(BaseModel):
    name: str
    text: str
    account_ids: list[int]
    kinds: list[str] = ["user", "group", "supergroup"]
    max_contacts: int = 0       # 0 = без ограничения
    per_minute: int = 10
    per_day: int = 0            # 0 = без ограничения, на аккаунт
    window_start: int = 0
    window_end: int = 24
    tz: str = "Europe/Moscow"
    exclude: str = ""           # id или @username по строке


@app.get("/api/campaigns", dependencies=[Depends(auth)])
async def list_campaigns(con=Depends(get_db)):
    rows = await con.fetch(
        "select c.*, "
        "count(t.id) filter (where t.status='pending') as pending, "
        "count(t.id) filter (where t.status='sent') as sent, "
        "count(t.id) filter (where t.status='failed') as failed "
        "from campaigns c left join targets t on t.campaign_id=c.id group by c.id order by c.id desc")
    return [dict(r) for r in rows]


@app.post("/api/campaigns", dependencies=[Depends(auth)])
async def create_campaign(b: CampaignIn, con=Depends(get_db)):
    if not b.account_ids or not b.text.strip():
        raise HTTPException(400, "Нужны текст и хотя бы один аккаунт")
    if not 1 <= b.per_minute <= 20:
        raise HTTPException(400, "per_minute: от 1 до 20")
    try:
        ZoneInfo(b.tz)
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "Неизвестный часовой пояс")
    exclude = {l.strip().lower().lstrip("@") for l in b.exclude.splitlines() if l.strip()}
    chats = await con.fetch(
        "select account_id, chat_id, title, username from chats "
        "where account_id=any($1) and kind=any($2) order by account_id, chat_id", b.account_ids, b.kinds)
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
        "insert into campaigns(name, text, account_ids, kinds, max_contacts, per_minute, per_day, "
        "window_start, window_end, tz) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) returning id",
        b.name, b.text, b.account_ids, b.kinds, b.max_contacts, b.per_minute, b.per_day,
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
    await con.execute("update campaigns set status=$2 where id=$1 and status<>'done'", cid, b.status)
    return {"ok": True}


@app.delete("/api/campaigns/{cid}", dependencies=[Depends(auth)])
async def delete_campaign(cid: int, con=Depends(get_db)):
    await con.execute("delete from campaigns where id=$1", cid)
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
                text = c["text"].replace("{name}", (t["title"] or "").split(" ")[0])
                status, err, stop = "sent", None, False
                try:
                    await client.send_message(t["chat_id"], text)
                except errors.FloodWaitError as e:
                    status, err, stop = "pending", None, True
                    await con.execute("update accounts set blocked_until=$2 where id=$1", aid,
                                      now + timedelta(seconds=e.seconds + 5))
                except errors.PeerFloodError:
                    status, err, stop = "pending", None, True
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
        await con.execute(SCHEMA)
        camps = await con.fetch("select * from campaigns where status='running'")
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
PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Рассылка</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--tx:#1b1f24;--mut:#6b7480;--ac:#2563eb;--bd:#e3e6ea}
@media(prefers-color-scheme:dark){:root{--bg:#14171a;--card:#1d2126;--tx:#e8eaed;--mut:#98a1ab;--ac:#5b8def;--bd:#2c323a}}
*{box-sizing:border-box}body{margin:0;font:15px system-ui,sans-serif;background:var(--bg);color:var(--tx)}
main{max-width:860px;margin:0 auto;padding:16px}h1{font-size:20px}h2{font-size:16px;margin:0 0 10px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px;margin-bottom:14px}
input,textarea,select,button{font:inherit;color:inherit;background:var(--bg);border:1px solid var(--bd);border-radius:7px;padding:8px}
button{background:var(--ac);color:#fff;border:0;cursor:pointer}button.sec{background:var(--bg);color:var(--tx);border:1px solid var(--bd)}
label{display:block;font-size:13px;color:var(--mut);margin:8px 0 3px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.row>*{flex:1;min-width:130px}
.item{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;padding:8px 0;border-top:1px solid var(--bd)}
.mut{color:var(--mut);font-size:13px}.err{color:#d33}.btns{display:flex;gap:6px;flex-wrap:wrap}
#msg{position:fixed;top:12px;left:50%;transform:translateX(-50%);max-width:92vw;padding:10px 14px;border-radius:8px;
background:#1b1f24;color:#fff;display:none;z-index:9;white-space:pre-wrap}#msg.bad{background:#d33}
</style></head><body><div id="msg"></div><main id="app"></main><script>
function note(t,bad){const m=document.querySelector('#msg');m.textContent=t;m.className=bad?'bad':'';m.style.display='block';
 clearTimeout(note.t);note.t=setTimeout(()=>m.style.display='none',bad?15000:6000)}
const $=s=>document.querySelector(s),app=$('#app');
async function api(m,u,b){const r=await fetch(u,{method:m,headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined});
 if(r.status==401&&u!=='/api/login'){login();throw 0}const d=await r.json().catch(()=>({}));
 if(!r.ok){note(d.detail||('Ошибка '+r.status),1);throw d}return d}
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function login(){app.innerHTML=`<div class="card" style="max-width:340px;margin:60px auto"><h2>Вход</h2>
<input id=pw type=password placeholder="Пароль" style="width:100%"><br><br><button id=go style="width:100%">Войти</button></div>`;
 const go=async()=>{try{await api('POST','/api/login',{password:$('#pw').value})}catch{return}main()};
 $('#go').onclick=go;$('#pw').onkeydown=e=>e.key==='Enter'&&go()}
async function main(){
 let accs,camps;try{[accs,camps]=await Promise.all([api('GET','/api/accounts'),api('GET','/api/campaigns')])}catch{return}
 app.innerHTML=`<div class="row" style="justify-content:space-between"><h1>Рассылка</h1><button class=sec id=out style="flex:0">Выйти</button></div>
 <div class=card><h2>Аккаунты Telegram</h2>${accs.map(a=>`<div class=item><div><b>${esc(a.name)}</b> ${esc(a.phone)}
 <div class=mut>${esc(a.status)} · чатов: ${a.chats}${a.blocked_until?' · пауза до '+new Date(a.blocked_until).toLocaleString():''}</div></div>
 <div class=btns>${a.status==='code_sent'?`<button onclick="code(${a.id})">Ввести код</button>`:`<button class=sec onclick="sync(${a.id},this)">Синхронизировать чаты</button>`}
 <button class=sec onclick="delAcc(${a.id})">Удалить</button></div></div>`).join('')||'<div class=mut>Пока нет аккаунтов</div>'}
 <h2 style="margin-top:14px">Добавить аккаунт</h2><div class=row><input id=an placeholder="Название"><input id=ap placeholder="Телефон +7..."></div>
 <div class=row style="margin-top:8px"><input id=ai placeholder="api_id"><input id=ah placeholder="api_hash"><button id=aa>Получить код</button></div>
 <div class=mut style="margin-top:6px">api_id и api_hash берутся на my.telegram.org</div></div>
 <div class=card><h2>Новая рассылка</h2>
 <label>Название</label><input id=cn style="width:100%"><label>Текст ({name} — первое слово названия чата)</label><textarea id=ct rows=4 style="width:100%"></textarea>
 <label>Аккаунты</label><div class=row>${accs.filter(a=>a.status==='active').map(a=>`<label style="margin:0"><input type=checkbox class=ca value=${a.id} checked> ${esc(a.name)}</label>`).join('')}</div>
 <label>Типы чатов</label><div class=row>${['user','group','supergroup','channel'].map(k=>`<label style="margin:0"><input type=checkbox class=ck value=${k} ${k!=='channel'?'checked':''}> ${k}</label>`).join('')}</div>
 <div class=row><div><label>Сообщений в минуту (на аккаунт)</label><input id=pm type=number value=10 min=1 max=20></div>
 <div><label>Макс. в день на аккаунт (0 — без лимита)</label><input id=pd type=number value=0></div>
 <div><label>Макс. контактов всего (0 — все)</label><input id=mc type=number value=0></div></div>
 <div class=row><div><label>Отправлять с (час)</label><input id=ws type=number value=9 min=0 max=23></div>
 <div><label>до (час)</label><input id=we type=number value=20 min=1 max=24></div>
 <div><label>Часовой пояс</label><input id=tz value="Europe/Moscow"></div></div>
 <label>Исключить (id или @username, по строке)</label><textarea id=ex rows=2 style="width:100%"></textarea><br><br><button id=cc>Создать (на паузе)</button></div>
 <div class=card><h2>Рассылки</h2>${camps.map(c=>`<div class=item><div><b>${esc(c.name)}</b> <span class=mut>${esc(c.status)}</span>
 <div class=mut>отправлено ${c.sent} · в очереди ${c.pending} · ошибок ${c.failed} · ${c.per_minute}/мин · ${c.window_start}–${c.window_end} ч</div></div>
 <div class=btns>${c.status==='running'?`<button class=sec onclick="st(${c.id},'paused')">Пауза</button>`:c.status!=='done'?`<button onclick="st(${c.id},'running')">Запустить</button>`:''}
 <button class=sec onclick="delC(${c.id})">Удалить</button></div></div>`).join('')||'<div class=mut>Пока нет рассылок</div>'}</div>`;
 $('#out').onclick=async()=>{await api('POST','/api/logout');login()};
 $('#aa').onclick=async()=>{await api('POST','/api/accounts',{name:$('#an').value,phone:$('#ap').value,api_id:+$('#ai').value,api_hash:$('#ah').value});main()};
 $('#cc').onclick=async()=>{const r=await api('POST','/api/campaigns',{name:$('#cn').value,text:$('#ct').value,
  account_ids:[...document.querySelectorAll('.ca:checked')].map(x=>+x.value),kinds:[...document.querySelectorAll('.ck:checked')].map(x=>x.value),
  per_minute:+$('#pm').value,per_day:+$('#pd').value,max_contacts:+$('#mc').value,window_start:+$('#ws').value,window_end:+$('#we').value,tz:$('#tz').value,exclude:$('#ex').value});
  note('Создано, контактов: '+r.targets+'. Нажмите «Запустить».');main()}}
async function code(id){const c=prompt('Код из Telegram');if(!c)return;const p=prompt('Пароль 2FA (если нет — оставьте пустым)')||null;await api('POST',`/api/accounts/${id}/code`,{code:c,password:p});main()}
async function sync(id,b){b.disabled=true;b.textContent='Идёт…';try{const r=await api('POST',`/api/accounts/${id}/sync`);note('Чатов: '+r.synced)}finally{main()}}
async function delAcc(id){if(confirm('Удалить аккаунт?')){await api('DELETE','/api/accounts/'+id);main()}}
async function delC(id){if(confirm('Удалить рассылку?')){await api('DELETE','/api/campaigns/'+id);main()}}
async function st(id,s){await api('POST',`/api/campaigns/${id}/status`,{status:s});main()}
api('GET','/api/me').then(main).catch(e=>{if(e!==0)login()});
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return PAGE
