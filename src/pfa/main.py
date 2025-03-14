from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def read_root():
    return {"message": "Hello, World!"}
@app.get("/nihao")
async def nihao():
    return {"message": "nihao"}

from .some import public_key_pem
@app.get("/api/login/publickey")
async def get_public_key():
    return {"public_key": public_key_pem}

@app.post("/api/login/register")
async def register():
    return {"message": "注册成功"}

@app.post("/api/login/login")
async def bur():
    return {"message": "登录成功"}