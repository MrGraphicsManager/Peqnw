from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

import os
import uuid
import logging
import bcrypt
import jwt
import asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response, BackgroundTasks
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr

import httpx
import hmac
import hashlib


# ---------------- Mongo ----------------
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]


# ---------------- App ----------------
app = FastAPI()
api_router = APIRouter(prefix="/api")

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MIN = 60 * 24  # 1 day


# ---------------- Helpers ----------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_access_token(email: str) -> str:
    payload = {
        "sub": email,
        "role": "admin",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MIN),
        "type": "access",
    }
    return jwt.encode(payload, os.environ["JWT_SECRET"], algorithm=JWT_ALGORITHM)


async def get_admin(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, os.environ["JWT_SECRET"], algorithms=[JWT_ALGORITHM])
        if payload.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Forbidden")
        return {"email": payload["sub"], "role": "admin"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------- Models ----------------
class Pack(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    slug: str
    name: str
    version: str
    category: str = "Background Pack"  # free text: "3D Character", "GFX Pack", "Background Pack", etc.
    tagline: str
    description: str
    price: int  # INR (sticker price)
    image_url: str
    drive_link: str
    features: List[str] = []
    item_count: int = 0
    is_launched: bool = True
    discount_percent: int = 0  # 0-90
    sort_order: int = 0
    created_at: str = Field(default_factory=now_iso)


def effective_price(price: int, discount_percent: int) -> int:
    if discount_percent <= 0:
        return price
    pct = max(0, min(90, discount_percent))
    return max(1, round(price * (100 - pct) / 100))


class PackCreate(BaseModel):
    slug: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9-]+$")
    name: str = Field(min_length=2, max_length=120)
    version: str = Field(min_length=1, max_length=40)
    category: str = Field(default="", max_length=60)
    tagline: str = ""
    description: str = ""
    price: int = Field(ge=1, le=999999)
    image_url: str = ""
    drive_link: str = ""
    features: List[str] = []
    item_count: int = 0
    is_launched: bool = True
    discount_percent: int = Field(default=0, ge=0, le=90)


class PackUpdate(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None
    category: Optional[str] = None
    tagline: Optional[str] = None
    description: Optional[str] = None
    price: Optional[int] = None
    image_url: Optional[str] = None
    drive_link: Optional[str] = None
    features: Optional[List[str]] = None
    item_count: Optional[int] = None
    is_launched: Optional[bool] = None
    discount_percent: Optional[int] = Field(default=None, ge=0, le=90)
    sort_order: Optional[int] = None


class PackPublic(BaseModel):
    id: str
    slug: str
    name: str
    version: str
    category: str
    tagline: str
    description: str
    price: int  # effective (what user pays)
    original_price: int  # sticker price (before discount)
    discount_percent: int
    is_launched: bool
    image_url: str
    features: List[str]
    item_count: int


def to_public_pack(doc: dict) -> dict:
    price = doc.get("price", 0)
    discount = doc.get("discount_percent", 0) or 0
    return {
        "id": doc["id"],
        "slug": doc["slug"],
        "name": doc["name"],
        "version": doc["version"],
        "category": doc.get("category") or "",
        "tagline": doc.get("tagline", ""),
        "description": doc.get("description", ""),
        "price": effective_price(price, discount),
        "original_price": price,
        "discount_percent": discount,
        "is_launched": doc.get("is_launched", True),
        "image_url": doc.get("image_url", ""),
        "features": doc.get("features", []),
        "item_count": doc.get("item_count", 0),
    }


class OrderLookup(BaseModel):
    email: EmailStr
    utr: str = Field(min_length=4, max_length=64)


class OrderCreate(BaseModel):
    pack_id: str
    email: EmailStr
    utr: str = Field(min_length=6, max_length=64)


class Order(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pack_id: str
    pack_slug: str
    pack_name: str
    pack_price: int
    email: str
    utr: str = ""
    status: str = "pending"  # pending | approved | rejected
    drive_link: Optional[str] = None
    note: Optional[str] = None
    payment_method: str = "manual_upi"  # manual_upi | instamojo
    payment_request_id: Optional[str] = None
    payment_id: Optional[str] = None
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)


class OrderPublic(BaseModel):
    id: str
    pack_name: str
    pack_price: int
    email: str
    utr: str
    status: str
    drive_link: Optional[str] = None
    payment_method: str = "manual_upi"
    created_at: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# ---------------- Chat / Announcement models ----------------
class Conversation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    email: str = ""
    ai_enabled: bool = True
    closed: bool = False
    unread_admin: int = 0  # messages awaiting admin
    last_message_at: str = Field(default_factory=now_iso)
    last_preview: str = ""
    created_at: str = Field(default_factory=now_iso)


class ChatMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    conversation_id: str
    sender: str  # "customer" | "ai" | "admin"
    text: str
    created_at: str = Field(default_factory=now_iso)


class ChatStartRequest(BaseModel):
    name: str = Field(default="", max_length=80)
    email: str = Field(default="", max_length=120)


class ChatMessageRequest(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


class Settings(BaseModel):
    announcement_enabled: bool = False
    announcement_text: str = ""
    announcement_link: str = ""
    upi_id: str = ""
    upi_payee_name: str = ""
    upi_id_secondary: str = ""
    upi_payee_name_secondary: str = ""


class SettingsUpdate(BaseModel):
    announcement_enabled: Optional[bool] = None
    announcement_text: Optional[str] = Field(default=None, max_length=240)
    announcement_link: Optional[str] = Field(default=None, max_length=400)
    upi_id: Optional[str] = Field(default=None, max_length=120)
    upi_payee_name: Optional[str] = Field(default=None, max_length=120)
    upi_id_secondary: Optional[str] = Field(default=None, max_length=120)
    upi_payee_name_secondary: Optional[str] = Field(default=None, max_length=120)


# ---------------- Routes: Public ----------------
@api_router.get("/")
async def root():
    return {"message": "pean api"}


@api_router.get("/config")
async def get_config():
    settings_doc = await db.settings.find_one({"_id": "site"}, {"_id": 0}) or {}
    return {
        "upi_id": settings_doc.get("upi_id") or os.environ.get("UPI_ID", ""),
        "payee_name": settings_doc.get("upi_payee_name") or os.environ.get("UPI_PAYEE_NAME", "Pean"),
        "upi_id_secondary": settings_doc.get("upi_id_secondary", ""),
        "payee_name_secondary": settings_doc.get("upi_payee_name_secondary", ""),
        "announcement": {
            "enabled": bool(settings_doc.get("announcement_enabled", False)),
            "text": settings_doc.get("announcement_text", ""),
            "link": settings_doc.get("announcement_link", ""),
        },
    }


# ---------------- Settings (admin) ----------------
@api_router.get("/admin/settings")
async def admin_get_settings(admin: dict = Depends(get_admin)):
    doc = await db.settings.find_one({"_id": "site"}, {"_id": 0}) or {}
    return {
        "announcement_enabled": bool(doc.get("announcement_enabled", False)),
        "announcement_text": doc.get("announcement_text", ""),
        "announcement_link": doc.get("announcement_link", ""),
        "upi_id": doc.get("upi_id") or os.environ.get("UPI_ID", ""),
        "upi_payee_name": doc.get("upi_payee_name") or os.environ.get("UPI_PAYEE_NAME", ""),
        "upi_id_secondary": doc.get("upi_id_secondary", ""),
        "upi_payee_name_secondary": doc.get("upi_payee_name_secondary", ""),
    }


@api_router.put("/admin/settings")
async def admin_update_settings(payload: SettingsUpdate, admin: dict = Depends(get_admin)):
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not update:
        raise HTTPException(status_code=400, detail="No fields to update")
    await db.settings.update_one({"_id": "site"}, {"$set": update}, upsert=True)
    doc = await db.settings.find_one({"_id": "site"}, {"_id": 0}) or {}
    return {
        "announcement_enabled": bool(doc.get("announcement_enabled", False)),
        "announcement_text": doc.get("announcement_text", ""),
        "announcement_link": doc.get("announcement_link", ""),
        "upi_id": doc.get("upi_id") or os.environ.get("UPI_ID", ""),
        "upi_payee_name": doc.get("upi_payee_name") or os.environ.get("UPI_PAYEE_NAME", ""),
        "upi_id_secondary": doc.get("upi_id_secondary", ""),
        "upi_payee_name_secondary": doc.get("upi_payee_name_secondary", ""),
    }


# ---------------- Chat helpers ----------------
CHAT_SYSTEM_PROMPT = (
    "You are PEAN's friendly customer support assistant for an online store called pean (pean.in). "
    "We sell digital packs: 3D character models, GFX packs, and background packs. "
    "Customers pay via manual UPI to priyennaik@okhdfcbank, submit their UTR + email on checkout, "
    "and once the admin verifies the payment (usually within a few minutes, sometimes a few hours), "
    "the Google Drive link unlocks on their order status page. "
    "If they lost their order link, they can go to /my-orders and enter their email + UTR. "
    "Rules: "
    "1) Reply in 1-3 short sentences. "
    "2) Match the customer's language — if they write in Hindi or Hinglish, reply in Hinglish; if English, reply in English. "
    "3) Be warm, casual, and concise. "
    "4) Never share fake Drive links or guess order details — only the admin can verify payments. "
    "5) If a question is about a specific order, refund, or anything you cannot resolve, "
    "say 'Let me get the admin to reply here in a few minutes' and stop. "
    "6) Never make promises about delivery time beyond 'usually a few minutes, sometimes a few hours'."
)


async def _generate_ai_reply(conversation_id: str, latest_user_text: str) -> str:
    history_docs = await db.chat_messages.find(
        {"conversation_id": conversation_id}, {"_id": 0}
    ).sort("created_at", 1).to_list(20)

    # Build a single user prompt with prior turns as context, then the latest customer message.
    prior = history_docs[:-1] if history_docs else []
    context_lines = []
    for m in prior[-10:]:
        role = {"customer": "Customer", "ai": "You", "admin": "Admin"}.get(m["sender"], "Other")
        context_lines.append(f"{role}: {m['text']}")
    if context_lines:
        prompt = (
            "Conversation so far:\n"
            + "\n".join(context_lines)
            + f"\n\nLatest customer message: {latest_user_text}\n\nReply now."
        )
    else:
        prompt = latest_user_text

    chat = LlmChat(
        api_key=os.environ.get("EMERGENT_LLM_KEY", ""),
        session_id=conversation_id,
        system_message=CHAT_SYSTEM_PROMPT,
    ).with_model("anthropic", "claude-sonnet-4-6")

    try:
        reply = await chat.send_message(UserMessage(text=prompt))
        if not isinstance(reply, str):
            reply = str(reply)
        return reply.strip() or "Sorry, I couldn't generate a reply. Please wait — our admin will reply shortly."
    except Exception as e:
        logging.exception("AI reply failed: %s", e)
        return "I'm having trouble responding right now. Our admin will reply here in a few minutes."


async def _ai_reply_background(conversation_id: str, user_text: str):
    reply = await _generate_ai_reply(conversation_id, user_text)
    msg = ChatMessage(conversation_id=conversation_id, sender="ai", text=reply)
    await db.chat_messages.insert_one(msg.model_dump())
    await db.conversations.update_one(
        {"id": conversation_id},
        {"$set": {"last_message_at": msg.created_at, "last_preview": reply[:120]}},
    )


# ---------------- Chat (public customer) ----------------
@api_router.post("/chat/start")
async def chat_start(payload: ChatStartRequest):
    conv = Conversation(name=payload.name.strip(), email=payload.email.strip().lower())
    # initial system greeting from AI
    greet = ChatMessage(
        conversation_id=conv.id,
        sender="ai",
        text=(
            f"Hi {conv.name or 'there'}! 👋 I'm PEAN's support assistant. "
            "Ask me anything about your pack, payment, or order. "
            "If I can't help, our admin will jump in shortly."
        ),
    )
    conv.last_message_at = greet.created_at
    conv.last_preview = greet.text[:120]
    await db.conversations.insert_one(conv.model_dump())
    await db.chat_messages.insert_one(greet.model_dump())
    return {"id": conv.id}


@api_router.get("/chat/{conversation_id}/messages")
async def chat_get_messages(conversation_id: str, since: Optional[str] = None):
    query = {"conversation_id": conversation_id}
    if since:
        query["created_at"] = {"$gt": since}
    docs = await db.chat_messages.find(query, {"_id": 0}).sort("created_at", 1).to_list(500)
    return docs


@api_router.post("/chat/{conversation_id}/messages")
async def chat_post_message(
    conversation_id: str,
    payload: ChatMessageRequest,
    background_tasks: BackgroundTasks,
):
    conv = await db.conversations.find_one({"id": conversation_id}, {"_id": 0})
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    msg = ChatMessage(conversation_id=conversation_id, sender="customer", text=payload.text.strip())
    await db.chat_messages.insert_one(msg.model_dump())
    await db.conversations.update_one(
        {"id": conversation_id},
        {
            "$set": {"last_message_at": msg.created_at, "last_preview": msg.text[:120]},
            "$inc": {"unread_admin": 1},
        },
    )

    # Trigger AI reply asynchronously (only if AI enabled for this conversation)
    if conv.get("ai_enabled", True):
        background_tasks.add_task(_ai_reply_background, conversation_id, msg.text)

    return msg.model_dump()


# ---------------- Chat (admin) ----------------
@api_router.get("/admin/chat/conversations")
async def admin_chat_conversations(admin: dict = Depends(get_admin)):
    docs = await db.conversations.find({}, {"_id": 0}).sort("last_message_at", -1).to_list(200)
    return docs


@api_router.get("/admin/chat/{conversation_id}/messages")
async def admin_chat_get_messages(conversation_id: str, admin: dict = Depends(get_admin)):
    docs = await db.chat_messages.find({"conversation_id": conversation_id}, {"_id": 0}).sort("created_at", 1).to_list(500)
    # Mark unread as 0
    await db.conversations.update_one({"id": conversation_id}, {"$set": {"unread_admin": 0}})
    return docs


@api_router.post("/admin/chat/{conversation_id}/messages")
async def admin_chat_post_message(
    conversation_id: str,
    payload: ChatMessageRequest,
    admin: dict = Depends(get_admin),
):
    conv = await db.conversations.find_one({"id": conversation_id}, {"_id": 0})
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    msg = ChatMessage(conversation_id=conversation_id, sender="admin", text=payload.text.strip())
    await db.chat_messages.insert_one(msg.model_dump())
    # When admin replies, disable AI so it doesn't talk over the admin
    await db.conversations.update_one(
        {"id": conversation_id},
        {"$set": {
            "ai_enabled": False,
            "last_message_at": msg.created_at,
            "last_preview": msg.text[:120],
            "unread_admin": 0,
        }},
    )
    return msg.model_dump()


@api_router.put("/admin/chat/{conversation_id}/ai")
async def admin_chat_toggle_ai(
    conversation_id: str,
    enabled: bool,
    admin: dict = Depends(get_admin),
):
    res = await db.conversations.update_one(
        {"id": conversation_id}, {"$set": {"ai_enabled": enabled}}
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"ok": True, "ai_enabled": enabled}


@api_router.delete("/admin/chat/{conversation_id}")
async def admin_chat_delete(conversation_id: str, admin: dict = Depends(get_admin)):
    await db.conversations.delete_one({"id": conversation_id})
    await db.chat_messages.delete_many({"conversation_id": conversation_id})
    return {"ok": True}


@api_router.get("/packs", response_model=List[PackPublic])
async def list_packs():
    docs = await db.packs.find({}, {"_id": 0, "drive_link": 0}).sort([("sort_order", 1), ("price", 1)]).to_list(100)
    return [to_public_pack(d) for d in docs]


@api_router.get("/packs/{slug}", response_model=PackPublic)
async def get_pack(slug: str):
    doc = await db.packs.find_one({"slug": slug}, {"_id": 0, "drive_link": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Pack not found")
    return to_public_pack(doc)


# ---------------- Routes: Orders ----------------
@api_router.post("/orders", response_model=OrderPublic)
async def create_order(payload: OrderCreate):
    pack = await db.packs.find_one({"id": payload.pack_id}, {"_id": 0})
    if not pack:
        raise HTTPException(status_code=404, detail="Pack not found")
    if not pack.get("is_launched", True):
        raise HTTPException(status_code=400, detail="This pack isn't on sale yet")

    final_price = effective_price(pack["price"], pack.get("discount_percent", 0) or 0)
    order = Order(
        pack_id=pack["id"],
        pack_slug=pack["slug"],
        pack_name=pack["name"],
        pack_price=final_price,
        email=payload.email.lower(),
        utr=payload.utr.strip(),
    )
    await db.orders.insert_one(order.model_dump())
    return OrderPublic(**order.model_dump())


@api_router.get("/orders/{order_id}", response_model=OrderPublic)
async def get_order(order_id: str):
    doc = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Order not found")
    # only expose drive_link if approved
    if doc.get("status") != "approved":
        doc["drive_link"] = None
    return doc


@api_router.post("/orders/lookup", response_model=List[OrderPublic])
async def lookup_orders(payload: OrderLookup):
    docs = await db.orders.find(
        {"email": payload.email.lower(), "utr": payload.utr.strip()},
        {"_id": 0},
    ).sort("created_at", -1).to_list(50)
    if not docs:
        raise HTTPException(status_code=404, detail="No order matches that email + UTR")
    for d in docs:
        if d.get("status") != "approved":
            d["drive_link"] = None
    return docs


# ---------------- Instamojo payment gateway ----------------
def _instamojo_base() -> str:
    env = os.environ.get("INSTAMOJO_ENV", "prod").lower()
    return "https://test.instamojo.com" if env in ("test", "sandbox") else "https://www.instamojo.com"


def _instamojo_headers() -> dict:
    return {
        "X-Api-Key": os.environ.get("INSTAMOJO_API_KEY", ""),
        "X-Auth-Token": os.environ.get("INSTAMOJO_AUTH_TOKEN", ""),
    }


class InstamojoCheckoutRequest(BaseModel):
    pack_id: str
    email: EmailStr
    name: str = Field(default="Customer", max_length=80)


@api_router.post("/orders/instamojo/create")
async def instamojo_create(payload: InstamojoCheckoutRequest, request: Request):
    pack = await db.packs.find_one({"id": payload.pack_id}, {"_id": 0})
    if not pack:
        raise HTTPException(status_code=404, detail="Pack not found")
    if not pack.get("is_launched", True):
        raise HTTPException(status_code=400, detail="This pack isn't on sale yet")

    final_price = effective_price(pack["price"], pack.get("discount_percent", 0) or 0)

    order = Order(
        pack_id=pack["id"],
        pack_slug=pack["slug"],
        pack_name=pack["name"],
        pack_price=final_price,
        email=str(payload.email).lower(),
        utr="",
        payment_method="instamojo",
    )

    # Use a publicly reachable base URL for redirect/webhook so Instamojo can reach us
    base_url = os.environ.get("PUBLIC_BASE_URL") or str(request.base_url).rstrip("/")
    redirect_url = f"{base_url}/api/orders/instamojo/return?order_id={order.id}"
    webhook_url = f"{base_url}/api/orders/instamojo/webhook"

    body = {
        "purpose": f"pean · {pack['name']}"[:30],
        "amount": str(final_price),
        "buyer_name": payload.name.strip() or "Customer",
        "email": str(payload.email).lower(),
        "redirect_url": redirect_url,
        "webhook": webhook_url,
        "allow_repeated_payments": "False",
        "send_email": "False",
        "send_sms": "False",
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        try:
            resp = await client.post(
                f"{_instamojo_base()}/api/1.1/payment-requests/",
                data=body,
                headers=_instamojo_headers(),
            )
        except httpx.HTTPError as e:
            logging.exception("Instamojo create failed: %s", e)
            raise HTTPException(status_code=502, detail="Couldn't reach payment gateway")

    if resp.status_code >= 400:
        logging.error("Instamojo error %s: %s", resp.status_code, resp.text)
        raise HTTPException(status_code=502, detail="Payment gateway rejected the request")

    data = resp.json()
    pr = data.get("payment_request") or {}
    if not pr.get("longurl"):
        raise HTTPException(status_code=502, detail="Payment gateway returned no checkout URL")

    order.payment_request_id = pr.get("id")
    await db.orders.insert_one(order.model_dump())
    return {"order_id": order.id, "longurl": pr["longurl"]}


async def _verify_and_approve_instamojo(order_id: str, payment_id: str) -> bool:
    """Confirm a payment with Instamojo and mark the order approved (idempotent)."""
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        return False
    if order.get("status") == "approved":
        return True

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.get(
                f"{_instamojo_base()}/api/1.1/payments/{payment_id}/",
                headers=_instamojo_headers(),
            )
        except httpx.HTTPError:
            return False

    if resp.status_code >= 400:
        return False
    info = resp.json().get("payment") or {}
    status = (info.get("status") or "").lower()
    if status != "credit":
        return False

    pack = await db.packs.find_one({"id": order["pack_id"]}, {"_id": 0})
    drive_link = pack["drive_link"] if pack else None
    await db.orders.update_one(
        {"id": order_id},
        {"$set": {
            "status": "approved",
            "drive_link": drive_link,
            "payment_id": payment_id,
            "utr": payment_id,
            "updated_at": now_iso(),
        }},
    )
    return True


@api_router.get("/orders/instamojo/return")
async def instamojo_return(
    order_id: str,
    payment_id: Optional[str] = None,
    payment_request_id: Optional[str] = None,
    payment_status: Optional[str] = None,
):
    """Customer is redirected here by Instamojo after attempting payment."""
    site_base = os.environ.get("PUBLIC_BASE_URL", "")
    # If we cannot resolve a frontend base, fall back to relative.
    target = f"{site_base}/order/{order_id}" if site_base else f"/order/{order_id}"

    if payment_id:
        try:
            await _verify_and_approve_instamojo(order_id, payment_id)
        except Exception as e:
            logging.exception("instamojo return verify error: %s", e)
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=target, status_code=302)


@api_router.post("/orders/instamojo/webhook")
async def instamojo_webhook(request: Request):
    """Async confirmation from Instamojo. Verifies HMAC-SHA1 with auth_token."""
    form = await request.form()
    data = dict(form)
    mac = data.pop("mac", "")
    # MAC = HMAC-SHA1 over '|'-joined values of keys sorted alphabetically, using auth_token as the key.
    sorted_values = [str(data[k]) for k in sorted(data.keys())]
    msg = "|".join(sorted_values).encode("utf-8")
    expected = hmac.new(
        os.environ.get("INSTAMOJO_AUTH_TOKEN", "").encode("utf-8"),
        msg,
        hashlib.sha1,
    ).hexdigest()
    if not hmac.compare_digest(expected, mac):
        logging.warning("Instamojo webhook MAC mismatch")
        raise HTTPException(status_code=400, detail="Invalid signature")

    payment_id = data.get("payment_id")
    payment_request_id = data.get("payment_request_id")
    status = (data.get("status") or "").lower()
    if status != "credit" or not payment_id or not payment_request_id:
        return {"ok": True, "ignored": True}

    order = await db.orders.find_one({"payment_request_id": payment_request_id}, {"_id": 0})
    if not order:
        return {"ok": True, "ignored": True}
    await _verify_and_approve_instamojo(order["id"], payment_id)
    return {"ok": True}


# ---------------- Routes: Auth ----------------
@api_router.post("/auth/login")
async def login(payload: LoginRequest, response: Response):
    admin_email = os.environ["ADMIN_EMAIL"].lower()
    admin_password = os.environ["ADMIN_PASSWORD"]
    if payload.email.lower() != admin_email or payload.password != admin_password:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(admin_email)
    # No cookie set — token lives in memory only on the client, so refresh = signed out
    return {"email": admin_email, "role": "admin", "token": token}


@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    return {"ok": True}


@api_router.get("/auth/me")
async def me(admin: dict = Depends(get_admin)):
    return admin


# ---------------- Routes: Admin ----------------
@api_router.get("/admin/orders")
async def admin_list_orders(admin: dict = Depends(get_admin), status: Optional[str] = None):
    query = {}
    if status:
        query["status"] = status
    docs = await db.orders.find(query, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return docs


@api_router.post("/admin/orders/{order_id}/approve")
async def admin_approve_order(order_id: str, admin: dict = Depends(get_admin)):
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    pack = await db.packs.find_one({"id": order["pack_id"]}, {"_id": 0})
    drive_link = pack["drive_link"] if pack else None
    await db.orders.update_one(
        {"id": order_id},
        {"$set": {"status": "approved", "drive_link": drive_link, "updated_at": now_iso()}},
    )
    return {"ok": True}


@api_router.post("/admin/orders/{order_id}/reject")
async def admin_reject_order(order_id: str, admin: dict = Depends(get_admin)):
    res = await db.orders.update_one(
        {"id": order_id},
        {"$set": {"status": "rejected", "updated_at": now_iso()}},
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"ok": True}


@api_router.get("/admin/packs")
async def admin_list_packs(admin: dict = Depends(get_admin)):
    docs = await db.packs.find({}, {"_id": 0}).sort([("sort_order", 1), ("price", 1)]).to_list(100)
    return docs


@api_router.post("/admin/packs/{pack_id}/move")
async def admin_move_pack(pack_id: str, direction: str, admin: dict = Depends(get_admin)):
    if direction not in ("up", "down"):
        raise HTTPException(status_code=400, detail="direction must be 'up' or 'down'")
    docs = await db.packs.find({}, {"_id": 0, "id": 1, "sort_order": 1, "price": 1}).sort([("sort_order", 1), ("price", 1)]).to_list(100)
    # normalise sort_order to 0..N-1 if any duplicates / missing
    for idx, d in enumerate(docs):
        if d.get("sort_order") != idx:
            await db.packs.update_one({"id": d["id"]}, {"$set": {"sort_order": idx}})
            d["sort_order"] = idx
    idx = next((i for i, d in enumerate(docs) if d["id"] == pack_id), None)
    if idx is None:
        raise HTTPException(status_code=404, detail="Pack not found")
    swap = idx - 1 if direction == "up" else idx + 1
    if swap < 0 or swap >= len(docs):
        return {"ok": True, "moved": False}
    a, b = docs[idx], docs[swap]
    await db.packs.update_one({"id": a["id"]}, {"$set": {"sort_order": b["sort_order"]}})
    await db.packs.update_one({"id": b["id"]}, {"$set": {"sort_order": a["sort_order"]}})
    return {"ok": True, "moved": True}


@api_router.post("/admin/packs")
async def admin_create_pack(payload: PackCreate, admin: dict = Depends(get_admin)):
    existing = await db.packs.find_one({"slug": payload.slug})
    if existing:
        raise HTTPException(status_code=400, detail="A pack with this slug already exists")
    pack = Pack(**payload.model_dump())
    await db.packs.insert_one(pack.model_dump())
    return pack.model_dump()


@api_router.delete("/admin/packs/{pack_id}")
async def admin_delete_pack(pack_id: str, admin: dict = Depends(get_admin)):
    res = await db.packs.delete_one({"id": pack_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Pack not found")
    return {"ok": True}


@api_router.put("/admin/packs/{pack_id}")
async def admin_update_pack(pack_id: str, payload: PackUpdate, admin: dict = Depends(get_admin)):
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not update:
        raise HTTPException(status_code=400, detail="No fields to update")
    res = await db.packs.update_one({"id": pack_id}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Pack not found")
    doc = await db.packs.find_one({"id": pack_id}, {"_id": 0})
    return doc


# ---------------- Startup: seed packs ----------------
@app.on_event("startup")
async def seed_data():
    # Backfill: ensure all existing packs have a category set
    await db.packs.update_many(
        {"$or": [{"category": {"$exists": False}}, {"category": None}, {"category": ""}]},
        {"$set": {"category": "Background Pack"}},
    )
    count = await db.packs.count_documents({})
    if count == 0:
        packs = [
            Pack(
                slug="bgmi-4-4",
                name="BGMI 4.4 Background Pack",
                version="4.4",
                category="Background Pack",
                tagline="Cinematic edits, ready in seconds.",
                description="A curated set of high-resolution background plates tailored for BGMI 4.4 thumbnails, banners, and edits. Sharp, color-graded, and ready for your next viral upload.",
                price=49,
                image_url="https://images.unsplash.com/photo-1477346611705-65d1883cee1e?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjA2MTJ8MHwxfHNlYXJjaHwxfHxlcGljJTIwZGFyayUyMG1vdW50YWluc3xlbnwwfHx8fDE3ODE3NjA4MDV8MA&ixlib=rb-4.1.0&q=85",
                drive_link="https://drive.google.com/your-bgmi-4-4-link",
                features=[
                    "50+ 4K backgrounds",
                    "Cinematic color grading",
                    "PNG + JPG formats",
                    "Royalty-free for personal edits",
                ],
                item_count=50,
            ),
            Pack(
                slug="bgmi-4-5",
                name="BGMI 4.5 Background Pack",
                version="4.5",
                category="Background Pack",
                tagline="The new wave. Bigger, bolder, sharper.",
                description="The latest pack built for BGMI 4.5 — futuristic urban scenes, neon palettes, and dramatic skies. Plug into your edit pipeline instantly.",
                price=79,
                image_url="https://images.unsplash.com/photo-1513061379709-ef0cd1695189?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2Njd8MHwxfHNlYXJjaHwxfHxmdXR1cmlzdGljJTIwY2l0eSUyMG5pZ2h0fGVufDB8fHx8MTc4MTc2MDgwNXww&ixlib=rb-4.1.0&q=85",
                drive_link="https://drive.google.com/your-bgmi-4-5-link",
                features=[
                    "80+ 4K backgrounds",
                    "Futuristic + neon scenes",
                    "PNG + JPG + bonus presets",
                    "Royalty-free for personal edits",
                ],
                item_count=80,
            ),
        ]
        await db.packs.insert_many([p.model_dump() for p in packs])
        logging.info("Seeded default packs")


# ---------------- Wire up ----------------
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
