from fastapi import APIRouter, HTTPException, Header
from app.mailboxes.model import Mailbox
from app.domains.model import UserDomains
import requests
from dotenv import load_dotenv
import os

mailbox_router = APIRouter(prefix="/api/v1/mailboxes", tags=["Mailboxes"])

load_dotenv()
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

@mailbox_router.post("/create")
async def create_mailbox(sender_data: dict, user_id: int = Header(...)):
    domain = UserDomains.get_or_none(UserDomains.domain_id == sender_data.get("domain_id"), UserDomains.user == user_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    url = "https://api.sendgrid.com/v3/senders"
    headers = {"Authorization": f"Bearer {SENDGRID_API_KEY}", "Content-Type": "application/json"}
    response = requests.post(url, headers=headers, json=sender_data)
    if response.status_code != 201:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    mailbox_data = response.json()
    Mailbox.create(
        user=user_id, domain=domain.id, mailbox_id=mailbox_data["id"],
        nickname=mailbox_data["nickname"], from_email=mailbox_data["from"]["email"],
        from_name=mailbox_data["from"]["name"], reply_to_email=mailbox_data["reply_to"]["email"],
        reply_to_name=mailbox_data["reply_to"]["name"], address=mailbox_data["address"],
        city=mailbox_data["city"], state=mailbox_data["state"],
        zip_code=mailbox_data["zip"], country=mailbox_data["country"],
        verified_status=mailbox_data["verified"]["status"]
    )
    return {"message": "Mailbox created successfully", "mailbox": mailbox_data}
