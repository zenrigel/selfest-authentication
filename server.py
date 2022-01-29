import hashlib
import hmac
import base64
import imp
import json
from typing import Optional

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "39a7762c0331a5c7b456dba2b1f990b45ddb84724b2eed7faf9b8d79f3f59f1e"
PASSWORD_SALT = "b059e71f4ec997e92a05a90591139ae76eb4add1026379c0244fad972758606b"

def sign_data(data: str) -> str:
    """Returns signed data 'data'"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash


users = {
    "andrii@user.com": {
        "name": "Andrii",
        "password": "bb394778aedb592deb5e7567821aee958175e8395ec64a2b91135b7566f44304",
        "balance": 100_000
    },
    "john@user.com": {
        "name": "John",
        "password": "538172b8fd43968c659405ab44ccdfe928b594b24df305e60cd17ba2d2a8c11c",
        "balance": 500_000
    }
}


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open("templates/login_page.html", "r") as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Hello, {users[valid_username]['name']}!<br /> \
        Balance: {users[valid_username]['balance']}",
        media_type="text/html")


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "This user does not exist!"
            }), 
            media_type="application/json")

    response = Response(
        json.dumps({
            "success": True,
            "message": f"Hello, {user['name']}!<br /> Balance: {user['balance']}"
        }),
        media_type='application/json')

    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response