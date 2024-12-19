from fastapi import FastAPI
from app.config.config import ALL_MODELS, middlewareAPI
from app.config.database import ConfigDatabase
from app.users.routes import router_user
from app.tasks.routes import router_task

app = FastAPI()


app.include_router(router_user)
app.include_router(router_task)
middlewareAPI(app)
config = ConfigDatabase(ALL_MODELS)


@app.on_event("startup")
async def startup():
    if config.database.is_closed():
        config.database.connect()
        config.refresh_tables()


@app.on_event("shutdown")
async def shutdown():
    if not config.database.is_closed():
        config.database.close()
