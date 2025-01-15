from sqlite3 import IntegrityError
from fastapi import FastAPI, APIRouter,Header, HTTPException, Depends
from app.config.security import get_current_user
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
import random
from fastapi_mail import ConnectionConfig
import os
from dotenv import load_dotenv
import sendgrid
from sendgrid.helpers.mail import Mail
from datetime import datetime,timedelta
import secrets
from fastapi import Query
import urllib3
from pydantic import BaseModel
import certifi
import requests
from dynadotpy.client import Dynadot
from dynadotpy.client import SEARCH_RESPONSES
from typing import List
from app.users.model import User , OTP ,Server, UserServer, UserDomains, Mailbox
from app.users.schema import LoginSchema, UserSchema

from app.config.utils import (
    create_access_token,
    create_refresh_token,
    get_hashed_password,
    verify_password,
    verify_refresh_token,
)

router_user = APIRouter(prefix="/api/v1")
load_dotenv()
urllib3.disable_warnings()



# conf = ConnectionConfig(
#     MAIL_USERNAME="ahmednaeemlhr1012@gmail.com",
#     MAIL_PASSWORD="zecx vifq eufp hpfw",
#     MAIL_FROM="ahmednaeemlhr1012@gmail.com",
#     MAIL_PORT=587,
#     MAIL_SERVER="smtp.gmail.com",
#     MAIL_STARTTLS=True,   # Correct field for STARTTLS
#     MAIL_SSL_TLS=False,   # Correct field for SSL/TLS
#     USE_CREDENTIALS=True,
#     VALIDATE_CERTS=False  # Disable SSL certificate validation
# )


conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=int(os.getenv("MAIL_PORT")),
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_STARTTLS=os.getenv("MAIL_STARTTLS") == "True",
    MAIL_SSL_TLS=os.getenv("MAIL_SSL_TLS") == "True",
    USE_CREDENTIALS=os.getenv("USE_CREDENTIALS") == "True",
    VALIDATE_CERTS=os.getenv("VALIDATE_CERTS") == "True"
)



SENDGRID_API_KEY = "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"
DYNADOT_API_KEY = os.getenv("DYNADOT_API_KEY")

dynadot_client = Dynadot(api_key=DYNADOT_API_KEY)

# class DomainAuthRequest(BaseModel):
#     domain: str
#     subdomain: str = "email"  # Default value
#     custom_spf: bool = True   # Default value

class DomainAuthRequest(BaseModel):
    domain: str
    ip: str  # Add this field for the IP address

class DNSRecord(BaseModel):
    type: str
    host: str
    value: str
    ttl: int

class DomainAuthResponse(BaseModel):
    message: str
    dns_records: list[DNSRecord]
    domain_id: str


class DomainSearchRequest(BaseModel):
    domains: List[str]  # List of domains to search for

class DomainSearchResponse(BaseModel):
    domain: str
    result: str
    more_info: str = None


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
        "automatic_security": False
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
    

@router_user.get("/check-domain-authentication/{domain_id}")
async def check_domain_authentication(domain_id: str):
    """
    Check if a domain is authenticated with SendGrid.
    
    Args:
        domain_id (str): The domain ID to check.

    Returns:
        dict: Authentication status of the domain.
    """
    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        # Make a request to SendGrid's API
        response = requests.get(f"https://api.sendgrid.com/v3/whitelabel/domains/{domain_id}", headers=headers)
        
        # Check the status code and handle errors
        if response.status_code == 200:
            data = response.json()
            print(data)
            return {
                "domain_id": domain_id,
                "authenticated": data.get("valid", False),
                "domain": data.get("domain", "N/A")
            }
        elif response.status_code == 404:
            raise HTTPException(status_code=404, detail="Domain ID not found")
        else:
            raise HTTPException(status_code=response.status_code, detail=response.json().get("errors", "Unknown error"))
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=str(e))

    


def validate_whitelabel_domain(domain_id: str):
    """
    Validate the domain whitelabel using SendGrid API with SSL verification disabled.
    """
    validate_url = f"https://api.sendgrid.com/v3/whitelabel/domains/{domain_id}/validate"
    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type": "application/json"
    }

    # Send the POST request with SSL verification disabled
    response = requests.post(validate_url, headers=headers, verify=False)  # Disable SSL verification

    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {response.text}")

    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Error from SendGrid: {response.text}"
        )

    return response.json()



async def sendgrid_add_ip_to_domain(domain_id: str, ip: str):
    """
    Call SendGrid API to associate an IP with a domain.
    """
    url = SENDGRID_API_URL.format(domain_id=domain_id)
    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {"ip": ip}

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 200:
        return {"success": True}
    else:
        print(f"SendGrid API Error: {response.text}")
        return {"success": False, "error": response.text}




@router_user.post("/signup")
async def signup(user_data: UserSchema):
    try:
        if User.select().where(User.email == user_data.email).exists():
            raise HTTPException(status_code=400, detail="User already exists")

        # Hash password
        hashed_password = get_hashed_password(user_data.password)

        # Generate verification token
        token = secrets.token_urlsafe(32)
        expiration = datetime.utcnow() + timedelta(hours=24)

        # Create user
        user = User.create(
            first_name=user_data.first_name,
            email=user_data.email,
            password=hashed_password,
            verification_token=token,
            token_expires_at=expiration
        )

        # Generate verification link
        verification_link = f"http://127.0.0.1:8000/api/v1/verify-email?token={token}"

        # Send email with the verification link
        message = MessageSchema(
            subject="Verify Your Email",
            recipients=[user.email],
            body=f"Hello {user.first_name},\n\nPlease click the link below to verify your email:\n{verification_link}\n\nThis link will expire in 24 hours.",
            subtype="plain"
        )
        fm = FastMail(conf)
        await fm.send_message(message)

        return {"message": "Signup successful! Please check your email to verify your account."}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router_user.get("/verify-email")
async def verify_email(token: str = Query(...)):
    try:
        # Find the user with the given token
        user = User.get(User.verification_token == token)

        # Check if the token has expired
        if datetime.utcnow() > user.token_expires_at:
            raise HTTPException(status_code=400, detail="Verification token has expired")

        # Mark the user as verified
        user.is_verified = True
        user.verification_token = None
        user.token_expires_at = None
        user.save()

        return {"message": "Email verified successfully! You can now log in."}

    except User.DoesNotExist:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router_user.post("/auth")
async def auth(user_data: LoginSchema):
    try:
        # Fetch user from database
        user = User.get(User.email == user_data.email)

        # Ensure email is verified
        if not user.is_verified:
            raise HTTPException(status_code=400, detail="Email not verified. Please verify your email to log in.")

        # Verify password
        if not verify_password(user_data.password, user.password):
            raise HTTPException(status_code=400, detail="Invalid password")

        # Generate access and refresh tokens
        access_token = create_access_token(user.email)
        refresh_token = create_refresh_token(user.email)

        return {
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": user.id,  # Include user ID in the response
        }

    except User.DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))



@router_user.get("/userserver/ips")
async def get_sendgrid_ips(user_id: int = Header(...)):
    """
    Retrieve all IP addresses from SendGrid, associate them with the provided user ID,
    replace or add new entries in the database without duplicating, 
    and return all stored IP details for the user.
    """
    try:
        # Validate the user_id (Optional: Ensure it exists in the database)
        if not User.select().where(User.id == user_id).exists():
            raise HTTPException(status_code=404, detail="User not found")

        # SendGrid API call
        url = "https://api.sendgrid.com/v3/ips"
        headers = {
            "Authorization": f"Bearer {SENDGRID_API_KEY}",
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers)
        print(SENDGRID_API_KEY)

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Error from SendGrid: {response.text}"
            )

        # Parse SendGrid response JSON
        ips_data = response.json()

        for ip_info in ips_data:
            ip_address = ip_info.get("ip")
            if ip_address:
                # Check if the IP already exists for the user
                existing_entry = UserServer.select().where(
                    (UserServer.user == user_id) & (UserServer.ip == ip_address)
                ).first()

                # If IP doesn't exist, create a new entry
                if not existing_entry:
                    UserServer.create(user=user_id, ip=ip_address)

        # Retrieve all IP details for the user from UserServer table
        user_servers = UserServer.select().where(UserServer.user == user_id)
        db_ip_list = [{"id": record.id, "ip": record.ip, "created_at": record.created_at.isoformat()} for record in user_servers]
        db_ip_map = {record['ip']: record['id'] for record in db_ip_list}
        ip_list = ips_data 
        db_ips = {record['ip'] for record in db_ip_list}  # Get the set of IPs from db_ip_list
        # Filter and map ip_list to only include IPs present in db_ip_list
        filtered_ip_list = [
            {
                "id": db_ip_map[ip_data["ip"]],
                "ip": ip_data["ip"],
                "subusers": ip_data.get("subusers", []),
                "pools": ip_data.get("pools", []),
                "warmup": ip_data.get("warmup", False),
                "start_date": ip_data.get("start_date", None),
                "whitelabeled": ip_data.get("whitelabeled", False),
                "assigned_at": ip_data.get("assigned_at", None),
            }
            for ip_data in ip_list
           if ip_data["ip"] in db_ips
        ]
        return {
            "message": "SendGrid IP addresses retrieved and updated successfully!",
            "ips": filtered_ip_list
        }
    except Exception as e:
        print(f"Error retrieving SendGrid IPs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router_user.get("/userserver/{server_id}")
async def get_single_server(server_id: int, user_id: int = Header(...)):
    """
    Retrieve a single server from the database using Server.id.
    """
    try:
        # Validate the user_id
        if not User.select().where(User.id == user_id).exists():
            raise HTTPException(status_code=404, detail="User not found")

        # Fetch the server using the server_id and validate ownership
        server = UserServer.get_or_none((UserServer.id == server_id) & (UserServer.user == user_id))
        if not server:
            raise HTTPException(status_code=404, detail="Server not found or does not belong to the user")

        # Format the server details
        server_data = {
            "id": server.id,
            "ip": server.ip,
            "created_at": server.created_at.isoformat(),
        }

        return {
            "message": "Server retrieved successfully",
            "server": server_data,
        }
    except Exception as e:
        print(f"Error retrieving server: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router_user.post("/refresh")
async def refresh_tokens(refresh_token: str):
    try:
        email = verify_refresh_token(refresh_token)

        access_token = create_access_token(email)
        new_refresh_token = create_refresh_token(email)

        return {"access_token": access_token, "refresh_token": new_refresh_token}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# @router_user.post("/domains/create", response_model=DomainAuthResponse)
# async def create_whitelabel(request: DomainAuthRequest, user_id: int = Header(...)):
#     """
#     Create SendGrid domain authentication, store details in the database,
#     and return DNS records to the user.
#     """
#     try:
#         # Validate the user_id
#         if not User.select().where(User.id == user_id).exists():
#             raise HTTPException(status_code=404, detail="User not found")

#         # Call SendGrid to create the domain authentication
#         response = create_whitelabel_domain(
#             domain=request.domain,
#             subdomain=request.subdomain,
#             custom_spf=request.custom_spf
#         )

#         # Extract DNS records from SendGrid response
#         dns_records = [
#             DNSRecord(
#                 type="cname",
#                 host=response["dns"][key]["host"],
#                 value=response["dns"][key]["data"],
#                 ttl=3600  # Default TTL
#             )
#             for key in response["dns"]
#         ]

#         # Store the domain and DNS records in the UserDomains table
#         try:
#             UserDomains.create(
#                 user=user_id,
#                 domain_id=response["id"],
#                 domain=request.domain,
#                 subdomain=request.subdomain,
#                 custom_spf=request.custom_spf,
#                 dns_records=response["dns"]  # Store DNS records as JSON
#             )
#         except IntegrityError:
#             raise HTTPException(status_code=400, detail="Domain already exists for this user.")

#         # Return the response to the user
#         return DomainAuthResponse(
#             message="Domain authentication created successfully. Configure the following DNS records:",
#             dns_records=dns_records,
#             domain_id=str(response["id"])  # Convert integer to string
#         )

#     except Exception as e:
#         print(f"Error in whitelabel creation: {e}")  # Log the error
#         raise HTTPException(status_code=500, detail=str(e))


@router_user.post("/domains/create", response_model=DomainAuthResponse)
async def create_whitelabel(request: DomainAuthRequest, user_id: int = Header(...)):
    """
    Create SendGrid domain authentication, associate IP, store details in the database,
    and return DNS records to the user.
    """
    try:
        # Validate the user_id
        if not User.select().where(User.id == user_id).exists():
            raise HTTPException(status_code=404, detail="User not found")

        # Validate the IP by fetching it from the servers table
        server = UserServer.select().where(UserServer.id == request.ip).first()
        if not server:
            raise HTTPException(status_code=404, detail="IP address not found in servers table")

        # Call SendGrid to create the domain authentication
        response = create_whitelabel_domain(
            domain=request.domain,
            subdomain='mail',
            custom_spf=False
        )


        # Parse the DNS records from the response
        dns_records = []
        for key, record in response["dns"].items():
            dns_records.append(
                DNSRecord(
                    type=record["type"],
                    host=record["host"],
                    value=record["data"],
                    ttl=3600  # Default TTL
                )
            )

        # Associate the provided IP with the created domain
        domain_id = response["id"]
        ip_association_response = associate_ip_with_domain(domain_id, server.ip)

        # Store the domain, DNS records, and IP in the UserDomains table
        try:
            UserDomains.create(
                user=user_id,
                domain_id=domain_id,
                domain=request.domain,
                subdomain='mail',
                custom_spf=True,
                dns_records=response["dns"],  
                server_id=server.id,
            )
        except IntegrityError:
            raise HTTPException(status_code=400, detail="Domain already exists for this user.")

        # Map the status of DNS validity for a better user response
        dns_status = {
            "mail_server": response["dns"]["mail_server"]["valid"],
            "subdomain_spf": response["dns"]["subdomain_spf"]["valid"],
            "dkim": response["dns"]["dkim"]["valid"]
        }

        # Return the response to the user
        return DomainAuthResponse(
            message="Domain authentication created successfully. Configure the following DNS records:",
            dns_records=dns_records,
            domain_id=str(domain_id),  # Convert integer to string
            ip_association_response=ip_association_response,  # Include the IP association response
            dns_status=dns_status
        )

    except Exception as e:
        print(f"Error in whitelabel creation: {e}")  # Log the error
        raise HTTPException(status_code=500, detail=str(e))


@router_user.get("/user/domains")
async def get_user_whitelabel_domains(user_id: int = Header(...), userserver_id: int = Header(...)):
    """
    Fetch all whitelabel domain information for the given user ID and associated UserServer,
    including validation status from SendGrid.
    """
    try:
        # Validate the user_id
        if not User.select().where(User.id == user_id).exists():
            raise HTTPException(status_code=404, detail="User not found")

        # Validate the userserver_id
        user_server = UserServer.select().where(UserServer.id == userserver_id, UserServer.user == user_id).first()
        if not user_server:
            raise HTTPException(status_code=404, detail="UserServer not found for the given user")

        # Fetch all domains associated with the given UserServer
        user_domains = UserDomains.select().where(UserDomains.server_id == userserver_id)

        # Check if the UserServer has any associated domains
        if not user_domains.exists():
            return {
                "message": "No domains found for the provided UserServer.",
                "domains": []
            }

        # Fetch all authenticated domains from SendGrid
        sendgrid_url = "https://api.sendgrid.com/v3/whitelabel/domains"
        headers = {
            "Authorization": f"Bearer {SENDGRID_API_KEY}",
            "Content-Type": "application/json"
        }
        sendgrid_response = requests.get(sendgrid_url, headers=headers)

        if sendgrid_response.status_code != 200:
            raise HTTPException(
                status_code=500,
                detail="Failed to fetch authenticated domains from SendGrid"
            )

        sendgrid_domains = sendgrid_response.json()

        # Map SendGrid domains for quick lookup
        sendgrid_domains_map = {
            domain["domain"]: domain for domain in sendgrid_domains
        }

        # Match and validate user domains
        domains_list = []
        for domain in user_domains:
            sendgrid_domain = sendgrid_domains_map.get(domain.domain)
            is_valid = sendgrid_domain.get("valid", False) if sendgrid_domain else False

            # Mark the domain validity in the database
            domain.is_valid = is_valid
            domain.save()

            # Append domain info to the list
            domains_list.append({
                "domain_id": domain.domain_id,
                "domain": domain.domain,
                "subdomain": domain.subdomain,
                "custom_spf": domain.custom_spf,
                "dns_records": sendgrid_domain.get('dns') if sendgrid_domain else False,
                "mailbox_count": Mailbox.select().where(Mailbox.domain == domain).count(),
                "created_at": domain.created_at,
                "is_valid": is_valid
            })

        return {
            "message": "Whitelabel domains retrieved successfully.",
            "domains": domains_list
        }

    except Exception as e:
        print(f"Error fetching user whitelabel domains: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router_user.post("/whitelabel/validate/{domain_id}")
async def validate_whitelabel(domain_id: str):
    """
    Validate SendGrid domain authentication after DNS records are added.
    """
    try:
        validation_response = validate_whitelabel_domain(domain_id)
        return {
            "message": "Domain validated successfully!",
            "validation_result": validation_response
        }
    except Exception as e:
        print(f"Validation error: {e}")  # Log the error for debugging
        raise HTTPException(status_code=500, detail=str(e))
    

@router_user.post("/mailboxes/create")
async def create_mailbox(sender_data: dict, user_id: int = Header(...)):
    """
    Create a mailbox under a specific domain for the logged-in user.
    """
    try:
        # Validate the user_id
        user = User.get_or_none(User.id == user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Validate the domain_id
        domain = UserDomains.get_or_none(UserDomains.domain_id == sender_data.get("domain_id"), UserDomains.user == user_id)
        if not domain:
            raise HTTPException(status_code=404, detail="Domain not found for the user")

        # Extract the domain part from the "from_email"
        from_email = sender_data.get("from_email")
        if not from_email or "@" not in from_email:
            raise HTTPException(status_code=400, detail="Invalid 'from_email' provided")

        email_domain = from_email.split("@")[1]  # Get the domain part after '@'

        # Check if the email domain matches the user's domains
        if not UserDomains.select().where((UserDomains.user == user_id) & (UserDomains.domain == email_domain)).exists():
            raise HTTPException(
                status_code=400,
                detail=f"The domain '{email_domain}' is not associated with the user."
            )

        # Prepare the payload for SendGrid sender API
        sender_payload = {
            "nickname": sender_data.get("nickname"),
            "from": {
                "email": sender_data.get("from_email"),
                "name": sender_data.get("from_name"),
            },
            "reply_to": {
                "email": sender_data.get("reply_to_email"),
                "name": sender_data.get("reply_to_name"),
            },
            "address": sender_data.get("address"),
            "address_2": sender_data.get("address_2"),
            "city": sender_data.get("city"),
            "state": sender_data.get("state"),
            "zip": sender_data.get("zip"),
            "country": sender_data.get("country"),
        }

        # Call SendGrid API to create the mailbox
        url = "https://api.sendgrid.com/v3/senders"
        headers = {
            "Authorization": f"Bearer {SENDGRID_API_KEY}",
            "Content-Type": "application/json"
        }
        response = requests.post(url, headers=headers, json=sender_payload)

        if response.status_code != 201:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Error from SendGrid: {response.text}"
            )

        # Parse the response and store in the database
        mailbox_data = response.json()
        Mailbox.create(
            user=user_id,
            domain=domain.id,  # Link to the domain in our DB
            mailbox_id=mailbox_data["id"],
            nickname=mailbox_data["nickname"],
            from_email=mailbox_data["from"]["email"],
            from_name=mailbox_data["from"]["name"],
            reply_to_email=mailbox_data["reply_to"]["email"],
            reply_to_name=mailbox_data["reply_to"]["name"],
            address=mailbox_data["address"],
            address_2=mailbox_data.get("address_2"),
            city=mailbox_data["city"],
            state=mailbox_data["state"],
            zip_code=mailbox_data["zip"],
            country=mailbox_data["country"],
            verified_status=mailbox_data["verified"]["status"],
            created_at=datetime.fromtimestamp(mailbox_data["created_at"]),
            updated_at=datetime.fromtimestamp(mailbox_data["updated_at"]),
        )

        return {
            "message": "Mailbox created successfully",
            "mailbox": mailbox_data
        }

    except Exception as e:
        print(f"Error creating mailbox: {e}")
        raise HTTPException(status_code=500, detail=str(e))


import requests

@router_user.get("/user-mailboxes/{domain_id}")
async def get_mailboxes(domain_id: str, user_id: int = Header(...)):
    """
    Fetch all mailboxes for a specific domain and user, and include verification status
    from SendGrid for matched senders in the database.
    """
    try:
        # Validate the user_id
        user = User.get_or_none(User.id == user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Validate the domain_id
        domain = UserDomains.get_or_none(UserDomains.domain_id == domain_id, UserDomains.user == user_id)
        if not domain:
            raise HTTPException(status_code=404, detail="Domain not found for the user")

        # Fetch mailboxes for the domain
        mailboxes = Mailbox.select().where(Mailbox.domain == domain.id)

        # Fetch verified senders from SendGrid API
        try:
            sendgrid_response = requests.get(
                "https://api.sendgrid.com/v3/verified_senders",
                headers={
                    "Authorization": f"Bearer {SENDGRID_API_KEY}",
                    "Content-Type": "application/json",
                },
            )
            if sendgrid_response.status_code != 200:
                raise Exception(f"SendGrid API Error: {sendgrid_response.text}")
            verified_senders = sendgrid_response.json().get("results", [])
        except Exception as e:
            print(f"Error fetching verified senders: {e}")
            verified_senders = []

        # Map verification statuses from SendGrid with database mailboxes
        verified_senders_map = {sender["from_email"]: sender for sender in verified_senders}
        mailbox_list = [
            {
                "mailbox_id": mailbox.mailbox_id,
                "nickname": mailbox.nickname,
                "from_email": mailbox.from_email,
                "from_name": mailbox.from_name,
                "reply_to_email": mailbox.reply_to_email,
                "reply_to_name": mailbox.reply_to_name,
                "verified_status": verified_senders_map.get(mailbox.from_email, {}).get("verified", "unknown"),
                "created_at": mailbox.created_at,
                "updated_at": mailbox.updated_at,
            }
            for mailbox in mailboxes
        ]

        return {
            "message": "Mailboxes retrieved successfully",
            "mailboxes": mailbox_list
        }
    except Exception as e:
        print(f"Error retrieving mailboxes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router_user.get("/user-mailboxes")
async def get_user_mailboxes(user_id: int = Header(...)):
    """
    Fetch all mailboxes for a specific user.
    """
    try:
        # Validate the user_id
        user = User.get_or_none(User.id == user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Fetch mailboxes linked to domains owned by the user
        mailboxes = (Mailbox
                     .select()
                     .join(UserDomains, on=(Mailbox.domain == UserDomains.id))
                     .where(UserDomains.user == user.id))
        
        mailbox_list = [
            {
                "mailbox_id": mailbox.mailbox_id,
                "nickname": mailbox.nickname,
                "from_email": mailbox.from_email,
                "from_name": mailbox.from_name,
                "reply_to_email": mailbox.reply_to_email,
                "reply_to_name": mailbox.reply_to_name,
                "verified_status": mailbox.verified_status,
                "created_at": mailbox.created_at,
                "updated_at": mailbox.updated_at,
                "domain": mailbox.domain.domain  # Include domain name in the response
            }
            for mailbox in mailboxes
        ]

        return {
            "message": "Mailboxes retrieved successfully for the user.",
            "mailboxes": mailbox_list
        }
    except Exception as e:
        print(f"Error retrieving user mailboxes: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    

''

@router_user.post("/new-domain/suggest-details")
async def fetch_domain_details(data: dict):
    query = data.get("query")
    """
    Fetch domain suggestions and availability details using GoDaddy's API.
    """
    try:
        # Step 1: Fetch domain suggestions
        suggestion_url = "https://api.ote-godaddy.com/v1/domains/suggest"
        headers = {
            "accept": "application/json",
            "Authorization": "sso-key 3mM44WkB29CfmG_NkfXzTUUynkTPAxtuU7hMf:MX4Da4e8Gk5re5VmBdqz7W",
        }
        suggestion_params = {
            "sources": "EXTENSION,KEYWORD_SPIN",
            "waitMs": 1000,
            "query": query,
        }

        # Fetch domain suggestions
        suggestion_response = requests.get(suggestion_url, headers=headers, params=suggestion_params)
        if suggestion_response.status_code != 200:
            raise HTTPException(
                status_code=suggestion_response.status_code,
                detail=f"Error fetching domain suggestions: {suggestion_response.text}",
            )

        suggested_domains = suggestion_response.json()

        # Extract domains from the suggestions
        domains = [item["domain"] for item in suggested_domains]

        # Debug: Log the extracted domains
        print(f"Suggested Domains: {domains}")

        # Step 2: Fetch availability details
        availability_url = "https://api.ote-godaddy.com/v1/domains/available?checkType=FAST"
        availability_headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "sso-key 3mM44WkB29CfmG_NkfXzTUUynkTPAxtuU7hMf:MX4Da4e8Gk5re5VmBdqz7W",
        }

        # Send a POST request with the list of domains
        availability_response = requests.post(
            availability_url, headers=availability_headers, json=domains
        )

        # Debug: Log the raw response
        print(f"Availability API Response: {availability_response.text}")

        # Check if the response is successful
        if availability_response.status_code != 200:
            raise HTTPException(
                status_code=availability_response.status_code,
                detail=f"Error fetching domain availability: {availability_response.text}",
            )

        # Parse availability details
        availability_details = availability_response.json().get("domains", [])

        # Combine suggestions and availability details into one response
        combined_results = []
        for domain in availability_details:
            combined_results.append({
                "domain": domain["domain"],
                "available": domain["available"],
                "price": domain.get("price"),
                "currency": domain.get("currency"),
                "period": domain.get("period"),
            })

        return combined_results

    except Exception as e:
        print(f"Error in fetch_domain_details: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch domain details")


@router_user.post("/domains/bulk-availability")
async def fetch_bulk_domain_availability(domains: list[str]):
    """
    Fetch bulk domain availability details using Mailreef's API.
    """
    try:
        # Define the Mailreef API endpoint and headers
        url = "https://api.mailreef.com/domains/bulk-availability"
        headers = {
            "Authorization": "Basic a2V5X3lqdkFqRWVra201Q081MFBSVmtTY0h1S2M=",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        # Create the payload
        payload = {
            "domains": domains
        }

        # Send a POST request to the Mailreef API
        response = requests.post(url, headers=headers, json=payload)

        # Debug: Log the raw response
        print(f"Mailreef API Response: {response.text}")

        # Check if the response is successful
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Error fetching bulk domain availability: {response.text}"
            )

        # Parse the response JSON
        availability_details = response.json()

        # Return the response
        return {
            "message": "Bulk domain availability fetched successfully",
            "domains": availability_details
        }

    except Exception as e:
        print(f"Error in fetch_bulk_domain_availability: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch bulk domain availability")


async def sendgrid_validate_domain(domain_id: str) -> dict:
    """
    Validate a domain using the SendGrid API.
    """
    url = f"https://api.sendgrid.com/v3/whitelabel/domains/{domain_id}/validate"
    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
    }

    response = requests.post(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"SendGrid Validation Error: {response.text}")
        return {"valid": False, "error": response.text}



# @router_user.post("/domains/{domain_id}/ips")
# async def add_ip_to_domain(
#     domain_id: str,
#     ip: str = Query(..., description="IP address to associate with the domain"),
#     user_id: int = Header(..., alias="user-id", description="User ID from the header")
# ):
#     """
#     Associate an IP address with a domain via SendGrid API.
#     """
#     try:
#         # Log received parameters for debugging
#         print(f"Received domain_id: {domain_id}, ip: {ip}, user_id: {user_id}")

#         # SendGrid API endpoint for associating an IP with a domain
#         sendgrid_url = f"https://api.sendgrid.com/v3/whitelabel/domains/{domain_id}/ips"
#         headers = {
#
#             "Content-Type": "application/json"
#         }
#         payload = {"ip": ip}

#         # Make the POST request to associate the IP with the domain
#         response = requests.post(sendgrid_url, headers=headers, json=payload)

#         # Check the response status
#         if response.status_code == 200:
#             print("SendGrid response:", response.json())
#             return {
#                 "message": "IP successfully associated with the domain",
#                 "sendgrid_response": response.json(),
#             }
#         else:
#             print("SendGrid API error:", response.text)
#             raise HTTPException(
#                 status_code=response.status_code,
#                 detail=f"SendGrid API error: {response.text}"
#             )
#     except Exception as e:
#         print(f"Error associating IP to domain: {e}")
#         raise HTTPException(status_code=500, detail=f"Internal Server Error: {e}")

@router_user.get("/domains/{domain_id}/validate")
async def validate_domain_whitelabel(domain_id: str, user_id: int = Header(...)):
    """
    Validate a domain whitelabel using SendGrid's API.
    """
    try:
        # Validate the user_id
        if not User.select().where(User.id == user_id).exists():
            raise HTTPException(status_code=404, detail="User not found")

        # Validate the domain_id exists in the database
        domain = UserDomains.get_or_none(UserDomains.domain_id == domain_id, UserDomains.user == user_id)
        if not domain:
            raise HTTPException(status_code=404, detail="Domain not found for the user")

        # Call SendGrid API to validate the domain
        validate_url = f"https://api.sendgrid.com/v3/whitelabel/domains/{domain_id}/validate"
        headers = {
            "Authorization": f"Bearer {SENDGRID_API_KEY}",
            "Content-Type": "application/json"
        }
        response = requests.post(validate_url, headers=headers)

        # Parse and handle the response
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Error validating domain: {response.text}"
            )

        validation_result = response.json()

        # Return the validation result
        return {
            "message": "Domain validation successful.",
            "validation_result": validation_result
        }

    except Exception as e:
        print(f"Error validating domain: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router_user.get("/domains/{domain_id}")
async def get_domain_by_id(domain_id: str, user_id: int = Header(...)):
    """
    Fetch a specific domain record based on domain_id for the logged-in user.
    """
    try:
        # Validate the user_id
        if not User.select().where(User.id == user_id).exists():
            raise HTTPException(status_code=404, detail="User not found")

        # Fetch the domain record
        domain = UserDomains.get_or_none(UserDomains.domain_id == domain_id, UserDomains.user == user_id)
        if not domain:
            raise HTTPException(status_code=404, detail="Domain not found for the given user")

        # Prepare the domain details
        domain_details = {
            "domain_id": domain.domain_id,
            "domain": domain.domain,
            "subdomain": domain.subdomain,
            "custom_spf": domain.custom_spf,
            "dns_records": domain.dns_records,
            "mailbox_count": Mailbox.select().where(Mailbox.domain == domain).count(),
            "created_at": domain.created_at,
        }

        return {
            "message": "Domain record retrieved successfully.",
            "domain": domain_details,
        }

    except Exception as e:
        print(f"Error fetching domain by ID: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router_user.get("/user/valid-domains")
async def get_valid_user_domains(user_id: int = Header(...), userserver_id: int = Header(...)):
    """
    Fetch only valid whitelabel domain information for the given user ID and associated UserServer.
    """
    try:
        # Validate the user_id
        if not User.select().where(User.id == user_id).exists():
            raise HTTPException(status_code=404, detail="User not found")

        # Validate the userserver_id
        user_server = UserServer.select().where(UserServer.id == userserver_id, UserServer.user == user_id).first()
        if not user_server:
            raise HTTPException(status_code=404, detail="UserServer not found for the given user")

        # Fetch domains associated with the given UserServer
        user_domains = UserDomains.select().where(UserDomains.server_id == userserver_id)
        if not user_domains.exists():
            return {
                "message": "No valid domains found for the provided UserServer.",
                "domains": []
            }

        # Fetch all authenticated domains from SendGrid
        sendgrid_url = "https://api.sendgrid.com/v3/whitelabel/domains"
        headers = {
            "Authorization": f"Bearer {SENDGRID_API_KEY}",
            "Content-Type": "application/json"
        }
        sendgrid_response = requests.get(sendgrid_url, headers=headers)

        if sendgrid_response.status_code != 200:
            raise HTTPException(
                status_code=500,
                detail="Failed to fetch authenticated domains from SendGrid"
            )

        sendgrid_domains = sendgrid_response.json()

        # Map SendGrid domains for quick lookup
        sendgrid_domains_map = {
            domain["domain"]: domain for domain in sendgrid_domains
        }

        # Match and validate user domains
        valid_domains_list = []
        for domain in user_domains:
            sendgrid_domain = sendgrid_domains_map.get(domain.domain)
            if sendgrid_domain and sendgrid_domain.get("valid", False):
                valid_domains_list.append({
                    "domain_id": domain.domain_id,
                    "domain": domain.domain,
                    "subdomain": domain.subdomain,
                    "custom_spf": domain.custom_spf,
                    "dns_records": domain.dns_records,
                    "mailbox_count": Mailbox.select().where(Mailbox.domain == domain).count(),
                    "created_at": domain.created_at
                })
            else:
                # Mark domain as invalid if not authenticated
                domain.is_valid = False
                domain.save()

        return {
            "message": "Valid whitelabel domains retrieved successfully.",
            "domains": valid_domains_list
        }

    except Exception as e:
        print(f"Error fetching valid user domains: {e}")
        raise HTTPException(status_code=500, detail=str(e))

