from fastapi import APIRouter, Depends

from app.config.celery import fetch_data_and_save_id_data
from app.config.security import get_current_user
from app.users.model import User

from app.config.config import ALL_MODELS, middlewareAPI


router_task = APIRouter(prefix="/api/v1")


@router_task.post("/task")
async def create_task(ip: str, current_user: User = Depends(get_current_user)):
    result = fetch_data_and_save_id_data.delay(ip, current_user["id"])
    return {"task_id": result.id}


@router_task.get("/status/{task_id}")
async def get_task_status(task_id: str):
    result = fetch_data_and_save_id_data.AsyncResult(task_id)
    if result.state == "PENDING":
        return {"status": "Task is pending"}
    elif result.state == "SUCCESS":
        return {"status": "Task is completed successfully"}
    elif result.state == "FAILURE":
        return {"status": "Task has failed"}
    else:
        return {"status": "Task status is unknown"}
