from fastapi import APIRouter, HTTPException, Header
from app.users.model import User, UserServer
import requests
from app.servers.model import Server
from dotenv import load_dotenv
import os


server_router = APIRouter(prefix="/api/v1/userserver", tags=["Servers"])
load_dotenv()
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

@server_router.get("/ips")
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
        ip_list = ips_data

        return {
            "message": "SendGrid IP addresses retrieved and updated successfully!",
            "ips": ip_list
        }
    except Exception as e:
        print(f"Error retrieving SendGrid IPs: {e}")
        raise HTTPException(status_code=500, detail=str(e))
