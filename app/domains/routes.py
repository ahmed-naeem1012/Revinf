from fastapi import APIRouter, HTTPException, Header, Query
from app.domains.model import UserDomains
from app.servers.model import Server
from app.users.model import User
import requests
from app.domains.schema import DomainAuthRequest, DomainAuthResponse
from dotenv import load_dotenv
import os

domain_router = APIRouter(prefix="/api/v1", tags=["Domains"])
load_dotenv()

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
SENDGRID_API_URL = "https://api.sendgrid.com/v3/whitelabel/domains"
SENDGRID_IP_URL_TEMPLATE = "https://api.sendgrid.com/v3/whitelabel/domains/{domain_id}/ips"

def create_whitelabel_domain(domain: str, subdomain: str, custom_spf: bool):
    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "domain": domain,
        "subdomain": subdomain,
        "custom_spf": custom_spf,
        "automatic_security": True
    }

    response = requests.post(SENDGRID_API_URL, headers=headers, json=payload)

    # Log for debugging
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {response.text}")

    if response.status_code != 201:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Error from SendGrid: {response.text}"
        )

    return response.json()

def associate_ip_with_domain(domain_id: int, ip: str):
    """
    Associate an IP address with a specific domain using SendGrid's API.
    """
    try:
        url = SENDGRID_IP_URL_TEMPLATE.format(domain_id=domain_id)
        headers = {
            "Authorization": f"Bearer {SENDGRID_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {"ip": ip}

        response = requests.post(url, headers=headers, json=payload)

        if response.status_code == 200:
            return response.json()
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"SendGrid IP association error: {response.text}"
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error associating IP: {e}")
    

@domain_router.post("/domains/create", response_model=DomainAuthResponse)
async def create_whitelabel(request: DomainAuthRequest, user_id: int = Header(...)):
    if not UserDomains.select().where(UserDomains.user == user_id).exists():
        raise HTTPException(status_code=404, detail="User not found")
    response = create_whitelabel_domain(
        domain=request.domain, subdomain=request.subdomain, custom_spf=request.custom_spf
    )
    domain_id = response["id"]
    associate_ip_with_domain(domain_id, request.ip)
    server, _ = Server.get_or_create(ip_address=request.ip)
    UserDomains.create(
        user=user_id, domain_id=domain_id, domain=request.domain,
        subdomain=request.subdomain, custom_spf=request.custom_spf,
        dns_records=response["dns"], server=server
    )
    return {"message": "Domain created successfully", "dns_records": response["dns"], "domain_id": domain_id}

@domain_router.get("/user/domains")
async def get_user_whitelabel_domains(user_id: int = Header(...)):
    """
    Fetch all whitelabel domain information for the given user ID.
    """
    try:
        # Validate the user_id
        if not User.select().where(User.id == user_id).exists():
            raise HTTPException(status_code=404, detail="User not found")

        # Fetch all domains associated with the user
        user_domains = UserDomains.select().where(UserDomains.user == user_id)

        # Check if the user has any domains
        if not user_domains.exists():
            return {
                "message": "No domains found for the user.",
                "domains": []
            }

        # Prepare response
        domains_list = [
            {
                "domain_id": domain.domain_id,
                "domain": domain.domain,
                "subdomain": domain.subdomain,
                "custom_spf": domain.custom_spf,
                "dns_records": domain.dns_records,
                "created_at": domain.created_at
            }
            for domain in user_domains
        ]

        return {
            "message": "Whitelabel domains retrieved successfully.",
            "domains": domains_list
        }
    except Exception as e:
        print(f"Error fetching user whitelabel domains: {e}")
        raise HTTPException(status_code=500, detail=str(e))
