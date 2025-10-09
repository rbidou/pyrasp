from fastapi import FastAPI, Request
from pyrasp.pyrasp import FastApiRASP
from pydantic import BaseModel

app = FastAPI()
rasp = FastApiRASP(app, conf='config.json')
print("**************")
print(rasp.get_blacklist())
print(rasp.get_config())
print(rasp.get_status())
print("**************")


class Item(BaseModel):
    name: str
    description: str | None = None


@app.get("/item/{item_id}")
async def root(request: Request,item_id: str):
    print(item_id)
    print(request.headers)
    return {
        "item": item_id
    }
