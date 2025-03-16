from fastapi import FastAPI,Request
from pydantic import BaseModel
app = FastAPI()

@app.get("/")
@app.get("/nihao")
async def read_root():
    return {"message": "Hello, Getech!"}


from .cryption import public_key_pem,private_key,server_register,server_login,client_encrypt_data

@app.get("/api/login/publickey")
async def get_public_key():
    return {"public_key": public_key_pem}

class Item(BaseModel):
    name: str
    key:str
@app.post("/debug/register")
async def dregister(item:Item):
    (name,key)=item
    _,name=name
    _,key=key
    return {"message":server_register(private_key,name,client_encrypt_data(public_key_pem,key))}
@app.post("/debug/login")
async def dlogin(item:Item):
    (name,key)=item
    _,name=name
    _,key=key
    return {"message":server_login(private_key,name,client_encrypt_data(public_key_pem,key))} 
import base64
@app.post("/api/login/register")
# 定义一个异步函数 register，用于注册某个项目
async def register(item:Item):
    # 从传入的 item 对象中解包出 name 和 ek 两个变量
    (name,key)=item
    _,name=name
    _,key=key
    return {"message":server_register(private_key,name,base64.b64decode(key))}

@app.post("/api/login/login")
async def bur(item:Item):
    (name,key)=item
    _,name=name
    _,key=key
    return {"message":server_login(private_key,name,base64.b64decode(key))}