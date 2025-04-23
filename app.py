from fastapi import FastAPI
import update

def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(update.router)
    return app


app = create_app()
