import pyotp
import httpx 
import base64
import asyncio
import logging
import hashlib
from typing import Literal
from urllib.parse import urlparse, parse_qs

#logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)

'''
###############################################################
---------------Enter Your Credentials Below--------------------
###############################################################
'''

FY_ID = "" #Fyers ID
PIN = "" # Login PIN
SECRET_KEY = ''
TOTP_KEY = "" 
APP_ID =  "" # First part of client id. eg. for XXXXXXX-100 it is XXXXXXX
APP_TYPE = "" # Second part of client id eg. for above example it is 100.
APP_ID_TYPE = "2"
RURL = 'https://127.0.0.1:5000/' 
MOB = "" # Your mobile number (Not required if you are using the get_auth_code function with userid.)

###############################################################


api_t1 = "https://api-t1.fyers.in/api/v3"
api_t2 = "https://api-t2.fyers.in/vagator/v2"

routes = {
    "get_userid" : f"{api_t2}/get_user_id_v2",
    "login_otp" : f"{api_t2}/send_login_otp_v2",
    "verify_otp" : f"{api_t2}/verify_otp",
    "verify_pin" : f"{api_t2}/verify_pin_v2",
    "get_token" : f"{api_t1}/token",
    "validate_auth" : f"{api_t1}/validate-authcode",
}

headers = {
        "Accept": "application/json",
        "Content-Type": "text/plain",
    }

def encode_item(item):
    encoded_pin = base64.b64encode(item.encode()).decode()
    return encoded_pin

mobileno_data = {
        "mobile_no": encode_item(MOB),
        "app_id": "2"
    }

userid_data = {
        "fy_id" : encode_item(FY_ID),
        "app_id": "2"
    }

token_data = {
        "fyers_id": FY_ID,
        "app_id": APP_ID,
        "redirect_uri": RURL,
        "appType": APP_TYPE,
        "code_challenge": "",
        "state": "None",
        "scope": "",
        "nonce": "",
        "response_type": "code",
        "create_cookie": True
    }

async def display(response):
    logging.info("Message :: {}".format(response.json()["message"]))

async def get_auth_code(method: Literal["mobile", "userid"]="mobile"):

    async with httpx.AsyncClient(headers= headers) as client:
        response = await client.post(
            routes["get_userid"] if method=="mobile" 
            else routes["login_otp"], 
            json = mobileno_data if method=="mobile"  
            else userid_data
            )

        if response.status_code == 200:
            req_key = response.json()["data"].get(FY_ID, {}).get("request_key", '')  if method=="mobile" else response.json().get("request_key", '') 

            response = await client.post(
                routes["verify_otp"], 
                json = {
                    "otp" : pyotp.TOTP(TOTP_KEY).now(),
                    "request_key" : req_key
                    }
                )
            if response.status_code == 200:
                req_key = response.json().get("request_key", '')
                
                response = await client.post(
                    routes["verify_pin"], 
                    json = {
                        "identifier" : encode_item(PIN),
                        "identity_type" : "pin",
                        "request_key" : req_key
                        }
                    )
                if response.status_code == 200:
                    access_token = response.json()["data"].get("access_token", '')
                    client.headers.update({"Authorization" : f"Bearer {access_token}"})

                    response = await client.post(
                        routes["get_token"], 
                        json =token_data
                        )
                    
                    if response.status_code == 308:
                        auth_url = response.json().get("Url", "")
                        query_params = parse_qs(urlparse(auth_url).query)
                        if 'auth_code' in query_params:
                            auth_code = query_params['auth_code'][0]
                            #print(auth_code)
                            return auth_code
                    else:
                        await display(response)
                else:
                    await display(response)
            else:
                await display(response)
        else:
            await display(response)

async def get_access_token(code):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            routes["validate_auth"],
            json = {
                "grant_type" : "authorization_code",
                "appIdHash" : hashlib.sha256(f"{APP_ID}-{APP_TYPE}:{SECRET_KEY}".encode()).hexdigest(),
                "code" : code,                                      
            }
        )
        if response.status_code == 200:
            access_token = response.json().get("access_token", "")
            return access_token
        else:
            await display(response)


if __name__ == "__main__":
    auth_code = asyncio.run(get_auth_code())
    access_token = asyncio.run(get_access_token(auth_code))
    print(access_token)
