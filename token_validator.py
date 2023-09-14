import json
import parameter
import urllib3
import certifi
import urllib.parse
import logging


def validate_access_token(token):
    KEYCLOAK_BASE_URI = parameter.get_parameter_store_key_value("KEYCLOAK_BASE_URI")
    KEYCLOAK_CLIENT_ID = parameter.get_parameter_store_key_value("KEYCLOAK_CLIENT_ID")
    KEYCLOAK_REALM_NAME = parameter.get_parameter_store_key_value("KEYCLOAK_REALM_NAME")
    KEYCLOAK_CLIENT_SECRET = parameter.get_parameter_store_key_value("KEYCLOAK_CLIENT_SECRET")

    KEYCLOAK_INTROSPECTION_ENDPOINT = (KEYCLOAK_BASE_URI + '/realms/' + KEYCLOAK_REALM_NAME
                                       + '/protocol/openid-connect/token/introspect')

    http = urllib3.PoolManager(ca_certs=certifi.where())
    data = {"client_id": KEYCLOAK_CLIENT_ID, "client_secret": KEYCLOAK_CLIENT_SECRET, "token": token}
    encoded_data = urllib.parse.urlencode(data)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    # bearerToken = "Bearer " + token
    # headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': bearerToken}

    try:
        request = http.request('POST', KEYCLOAK_INTROSPECTION_ENDPOINT, headers=headers, body=encoded_data)
        response_data = json.loads(request.data.decode('utf-8'))
        if response_data['active']:
            response = {
                'statusCode': 200,
                'isActive': response_data['active'],
                'error': ''
            }
        else:
            response = {
                'statusCode': 403,
                'isActive': False,
                'error': ''
            }
        logging.info("Access token has been validated successfully")
    except Exception as e:
        logging.error("Failed to validate access token for user with error : %s", str(e))
        response = {
            'statusCode': 403,
            'isActive': False,
            'error': 'Failed to validate access token for user with error : ' + str(e)
        }

    return json.dumps(response)
