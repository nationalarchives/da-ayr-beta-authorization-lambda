import json
import parameter
import urllib3
import certifi
import urllib.parse
import logging


def get_access_token(username, password):
    KEYCLOAK_BASE_URI = parameter.get_parameter_store_key_value("KEYCLOAK_BASE_URI")
    KEYCLOAK_CLIENT_ID = parameter.get_parameter_store_key_value("KEYCLOAK_CLIENT_ID")
    KEYCLOAK_REALM_NAME = parameter.get_parameter_store_key_value("KEYCLOAK_REALM_NAME")
    KEYCLOAK_CLIENT_SECRET = parameter.get_parameter_store_key_value(
        "KEYCLOAK_CLIENT_SECRET"
    )

    KEYCLOAK_ACCESS_TOKEN_URL = (
        KEYCLOAK_BASE_URI
        + "/realms/"
        + KEYCLOAK_REALM_NAME
        + "/protocol/openid-connect/token"
    )

    http = urllib3.PoolManager(ca_certs=certifi.where())
    data = {
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "grant_type": "password",
        "username": username,
        "password": password,
    }
    encoded_data = urllib.parse.urlencode(data)

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        request = http.request(
            "POST", KEYCLOAK_ACCESS_TOKEN_URL, headers=headers, body=encoded_data
        )
        response_data = json.loads(request.data.decode("utf-8"))
        response = {"statusCode": 200, "body": response_data["access_token"]}
        logging.info("Access token has been generated successfully")
    except Exception as e:
        logging.error("Failed to get access token for user with error : %s", str(e))
        response = {
            "statusCode": 403,
            "body": "Failed to get access token for user with error : " + str(e),
        }

    return json.dumps(response)
