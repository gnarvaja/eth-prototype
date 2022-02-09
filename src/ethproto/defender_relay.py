import time
import requests
from environs import Env

import boto3
from warrant.aws_srp import AWSSRP

env = Env()

DEFENDER_POOL = env.str("DEFENDER_POOL", "us-west-2_iLmIggsiy")
DEFENDER_CLIENT = env.str("DEFENDER_CLIENT", "1bpd19lcr33qvg5cr3oi79rdap")
DEFENDER_API_URL = env.str("DEFENDER_API_URL", "https://api.defender.openzeppelin.com")
DEFENDER_SPEED = env.str("DEFENDER_SPEED", None)

token = None
token_expires = None


def get_new_token():
    client = boto3.client("cognito-idp", region_name="us-west-2")
    aws = AWSSRP(
        username=env.str("DEFENDER_API_KEY"),
        password=env.str("DEFENDER_SECRET_KEY"),
        pool_id=DEFENDER_POOL,
        client_id=DEFENDER_CLIENT,
        client=client,
    )

    tokens = aws.authenticate_user()

    return (
        tokens["AuthenticationResult"]["AccessToken"],
        tokens["AuthenticationResult"]["ExpiresIn"] + time.time() - 60
    )


def get_token():
    global token
    global token_expires

    if token is None or time.time() >= token_expires:
        token, token_expires = get_new_token()

    return token


def send_transaction(tx):
    tx_for_defender = {k: v for (k, v) in tx.items() if k in ("to", "value", "data", "chainId")}
    tx_for_defender["gasLimit"] = tx["gas"]
    if DEFENDER_SPEED:
        tx_for_defender["speed"] = DEFENDER_SPEED

    token = get_token()

    resp = requests.post(
        DEFENDER_API_URL + "/txs",
        json=tx_for_defender,
        headers={
            "X-Api-Key": env.str("DEFENDER_API_KEY"),
            "Authorization": "Bearer %s" % token
        }
    )
    resp.raise_for_status()
    return resp.json()
