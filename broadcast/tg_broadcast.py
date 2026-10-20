"""Рассылка по рабочим чатам с нескольких Telegram-аккаунтов (Telethon).

Пишет только в чаты, которые есть в списке из CRM (--allow-file).

Команды:
  login  <имя>                  войти в аккаунт (код из Telegram), создаёт сессию
  chats                         выгрузить чаты всех аккаунтов в chats.csv (ничего не отправляет)
  send   --text-file msg.txt --allow-file crm.txt    разослать; --dry-run только показать план
"""
import argparse
import asyncio
import csv
import json
import random
import sys
from pathlib import Path

from telethon import TelegramClient, errors
from telethon.tl.types import Channel, Chat, User

BASE = Path(__file__).parent
ACCOUNTS_FILE = BASE / "accounts.json"   # [{"name": "a1", "api_id": 123, "api_hash": "..."}]
SESSIONS = BASE / "sessions"
EXCLUDE_FILE = BASE / "exclude.txt"      # по строке: id, @username или телефон, кому не писать
SENT_LOG = BASE / "sent.jsonl"           # журнал отправленного, позволяет продолжить после остановки
CHATS_CSV = BASE / "chats.csv"

PER_MINUTE = 10                           # лимит на каждый аккаунт
INTERVAL = 60 / PER_MINUTE
JITTER = 0.25                             # +-25% к паузе, чтобы не слать «по метроному»


def norm(value):
    return str(value).strip().lower().lstrip("@").lstrip("+")


def load_list(path):
    """Файл со списком id / @username / телефонов, по одному в строке."""
    if not path.exists():
        return set()
    return {norm(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()}


def load_accounts():
    if not ACCOUNTS_FILE.exists():
        sys.exit(f"Нет {ACCOUNTS_FILE.name}. Пример в accounts.example.json")
    return json.loads(ACCOUNTS_FILE.read_text(encoding="utf-8"))


def make_client(acc):
    SESSIONS.mkdir(exist_ok=True)
    return TelegramClient(str(SESSIONS / acc["name"]), acc["api_id"], acc["api_hash"])


def load_sent():
    sent = set()
    if SENT_LOG.exists():
        for line in SENT_LOG.read_text(encoding="utf-8").splitlines():
            sent.add(json.loads(line)["chat_id"])
    return sent


def kind_of(entity):
    if isinstance(entity, User):
        return "user"
    if isinstance(entity, Chat):
        return "group"
    if isinstance(entity, Channel):
        return "channel" if entity.broadcast else "supergroup"
    return "other"


def can_write(entity):
    """Исключаем ботов, удалённых, чужие каналы без прав публикации."""
    if isinstance(entity, User):
        return not (entity.bot or entity.deleted or entity.is_self or entity.support)
    if isinstance(entity, Chat):
        return not (entity.deactivated or entity.left)
    if isinstance(entity, Channel):
        if entity.left:
            return False
        if entity.broadcast:
            return bool(entity.creator or (entity.admin_rights and entity.admin_rights.post_messages))
        if entity.creator or entity.admin_rights:
            return True
        rights = entity.default_banned_rights
        return not (rights and rights.send_messages)
    return False


async def collect(acc, kinds):
    """Диалоги аккаунта, в которые можно писать."""
    rows = []
    async with make_client(acc) as client:
        async for d in client.iter_dialogs():
            e = d.entity
            k = kind_of(e)
            if k not in kinds or not can_write(e):
                continue
            rows.append({
                "account": acc["name"], "chat_id": d.id, "kind": k, "title": d.name,
                "username": getattr(e, "username", None) or "",
                "phone": getattr(e, "phone", None) or "",
            })
    return rows


def keys(row):
    return {norm(row["chat_id"]), norm(row["username"]), norm(row["phone"])} - {""}


def plan(all_rows, allow, exclude, sent):
    """Один чат — один аккаунт; только чаты из CRM-списка; без исключённых и уже отправленных."""
    seen, by_acc = set(), {}
    for r in all_rows:
        cid = r["chat_id"]
        k = keys(r)
        if cid in seen or cid in sent or not (k & allow) or (k & exclude):
            continue
        seen.add(cid)
        by_acc.setdefault(r["account"], []).append(r)
    return by_acc


async def cmd_login(args):
    acc = next((a for a in load_accounts() if a["name"] == args.name), None)
    if not acc:
        sys.exit("Нет такого аккаунта в accounts.json")
    client = make_client(acc)
    await client.start()  # спросит телефон, код и пароль 2FA в консоли
    me = await client.get_me()
    print(f"OK: {acc['name']} -> {me.first_name} (+{me.phone})")
    await client.disconnect()


async def gather_rows(kinds):
    rows = []
    for acc in load_accounts():
        rows += await collect(acc, kinds)
    return rows


async def cmd_chats(args):
    rows = await gather_rows(set(args.kinds.split(",")))
    with CHATS_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["account", "chat_id", "kind", "title", "username", "phone"])
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} чатов записано в {CHATS_CSV.name}")


async def worker(acc, rows, template, dry):
    sent_n = 0
    async with make_client(acc) as client:
        for r in rows:
            text = template.replace("{name}", r["title"].split(" ")[0])
            if dry:
                print(f"[dry] {acc['name']} -> {r['title']} ({r['kind']})")
                continue
            try:
                await client.send_message(r["chat_id"], text)
            except errors.FloodWaitError as e:
                print(f"[{acc['name']}] FloodWait {e.seconds}c, жду")
                await asyncio.sleep(e.seconds + 5)
                continue
            except errors.PeerFloodError:
                print(f"[{acc['name']}] PeerFlood: Telegram ограничил аккаунт, остановка")
                return
            except (errors.ChatWriteForbiddenError, errors.UserPrivacyRestrictedError,
                    errors.UserIsBlockedError, errors.ChatAdminRequiredError) as e:
                print(f"[{acc['name']}] пропуск {r['title']}: {type(e).__name__}")
                continue
            except Exception as e:  # noqa: BLE001
                print(f"[{acc['name']}] ошибка {r['title']}: {e!r}")
                continue
            sent_n += 1
            with SENT_LOG.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"chat_id": r["chat_id"], "account": acc["name"], "title": r["title"]},
                                   ensure_ascii=False) + "\n")
            print(f"[{acc['name']}] #{sent_n} -> {r['title']}")
            await asyncio.sleep(INTERVAL * random.uniform(1 - JITTER, 1 + JITTER))


async def cmd_send(args):
    template = Path(args.text_file).read_text(encoding="utf-8").strip()
    allow = load_list(Path(args.allow_file))
    if not allow:
        sys.exit("Список --allow-file пуст или не найден: отправлять некому")
    rows = await gather_rows(set(args.kinds.split(",")))
    by_acc = plan(rows, allow, load_list(EXCLUDE_FILE), load_sent())
    if args.limit:
        by_acc = {k: v[:args.limit] for k, v in by_acc.items()}
    total = sum(len(v) for v in by_acc.values())
    print(f"К отправке: {total} чатов; " + ", ".join(f"{k}: {len(v)}" for k, v in by_acc.items()))
    if total and not args.dry_run:
        eta = max(len(v) for v in by_acc.values()) / PER_MINUTE
        print(f"Ориентировочно {eta:.0f} мин. Ctrl+C остановит, повторный запуск продолжит.")
    accounts = {a["name"]: a for a in load_accounts()}
    await asyncio.gather(*(worker(accounts[n], v, template, args.dry_run) for n, v in by_acc.items()))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    kinds_help = "типы чатов через запятую: user,group,supergroup,channel"
    s = sub.add_parser("login"); s.add_argument("name"); s.set_defaults(fn=cmd_login)
    s = sub.add_parser("chats"); s.add_argument("--kinds", default="user,group,supergroup", help=kinds_help)
    s.set_defaults(fn=cmd_chats)
    s = sub.add_parser("send")
    s.add_argument("--text-file", required=True)
    s.add_argument("--allow-file", required=True, help="выгрузка из CRM: id / @username / телефон по строке")
    s.add_argument("--kinds", default="user,group,supergroup", help=kinds_help)
    s.add_argument("--limit", type=int, help="максимум чатов на аккаунт (для пробного запуска)")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_send)
    args = p.parse_args()
    asyncio.run(args.fn(args))


if __name__ == "__main__":
    main()
