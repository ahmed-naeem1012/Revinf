from celery import Celery
import ipdata
from app.tasks.model import Tasks
from decouple import config

app = Celery("tasks", broker=config("RABBITMQ_URL"), backend="rpc://")


@app.task
def fetch_data_and_save_id_data(ip, user_id):
    ipdata.api_key = config("IPDATA_API_KEY")
    response = ipdata.lookup(ip)

    Tasks.create(
        ip=ip,
        country_name=response["country_name"],
        city=response["city"],
        latitude=response["latitude"],
        longitude=response["longitude"],
        flag=response["flag"],
        continent_code=response["continent_code"],
        user_id=user_id,
    )

    return response
