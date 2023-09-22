import json
import logging
import keycloak
import parameter


def get_keycloak_openid_object():
    try:
        AWS_ENVIRONMENT = parameter.get_parameter_store_key_value("ENVIRONMENT_NAME")
        PREFIX = "/" + AWS_ENVIRONMENT + "/"
        KEYCLOAK_BASE_URI = parameter.get_parameter_store_key_value(PREFIX + "KEYCLOAK_BASE_URI")
        KEYCLOAK_CLIENT_ID = parameter.get_parameter_store_key_value(PREFIX + "KEYCLOAK_CLIENT_ID")
        KEYCLOAK_REALM_NAME = parameter.get_parameter_store_key_value(PREFIX + "KEYCLOAK_REALM_NAME")
        KEYCLOAK_CLIENT_SECRET = parameter.get_parameter_store_key_value(PREFIX + "KEYCLOAK_CLIENT_SECRET")

        keycloak_openid = keycloak.KeycloakOpenID(server_url=KEYCLOAK_BASE_URI,
                                                  client_id=KEYCLOAK_CLIENT_ID,
                                                  realm_name=KEYCLOAK_REALM_NAME,
                                                  client_secret_key=KEYCLOAK_CLIENT_SECRET)
        return keycloak_openid
    except Exception as e:
        logging.error("Error generating keycloak openid object with error : " + str(e))


def get_access_token(username, password, one_time_passcode=0):
    try:
        keycloak_openid = get_keycloak_openid_object()
        access_token_response = keycloak_openid.token(username, password, grant_type="password")
        if one_time_passcode > 0:
            access_token_response = keycloak_openid.token(username, password, grant_type="password",
                                                          totp=one_time_passcode)
        access_token_json = json.loads(json.dumps(access_token_response))
        token_response = {"statusCode": 200, "body": access_token_json["access_token"]}
        # return access_token_json["access_token"]
    except Exception as e:
        logging.error(str(e))
        token_response = {
            "statusCode": 403,
            "body": "Failed to get access token for user with error : " + str(e),
        }

    return json.dumps(token_response)


def validate_access_token(token):
    try:
        keycloak_openid = get_keycloak_openid_object()
        validate_token_response = keycloak_openid.introspect(token)  # token['access_token'])
        # print(validate_token_response)
        validate_token_json = json.loads(json.dumps(validate_token_response))
        if validate_token_json["active"]:
            response = {
                "statusCode": 200,
                "isActive": validate_token_json["active"],
                "error": "",
            }
        else:
            response = {"statusCode": 403, "isActive": False, "error": ""}

        return json.dumps(response)
    except Exception as e:
        logging.error(str(e))


def decode_access_token(token):
    try:
        AWS_ENVIRONMENT = parameter.get_parameter_store_key_value("ENVIRONMENT_NAME")
        PREFIX = "/" + AWS_ENVIRONMENT + "/"
        KEYCLOAK_REALM_PUBLIC_KEY = parameter.get_parameter_store_key_value(PREFIX + "KEYCLOAK_REALM_PUBLIC_KEY")
        KEYCLOAK_CLIENT_ID = parameter.get_parameter_store_key_value(PREFIX + "KEYCLOAK_CLIENT_ID")

        keycloak_openid = get_keycloak_openid_object()
        keycloak_public_key = ("-----BEGIN PUBLIC KEY-----\n" + KEYCLOAK_REALM_PUBLIC_KEY
                               + "\n-----END PUBLIC KEY-----")
        options = {"verify_signature": False, "verify_aud": False, "verify_exp": True,
                   "audience": KEYCLOAK_CLIENT_ID}
        decoded_token = keycloak_openid.decode_token(token, key=keycloak_public_key, options=options)
        decoded_token_response = {"statusCode": 200, "body": json.dumps(decoded_token)}
    except Exception as e:
        decoded_token_response = {
            "statusCode": 400,
            "body": "Failed to decode access token : " + str(e)
        }
    return json.dumps(decoded_token_response)


def check_user_group(token):
    group_exist = False
    try:
        AWS_ENVIRONMENT = parameter.get_parameter_store_key_value("ENVIRONMENT_NAME")
        PREFIX = "/" + AWS_ENVIRONMENT + "/"
        KEYCLOAK_AYR_USER_GROUP = parameter.get_parameter_store_key_value(PREFIX + "KEYCLOAK_AYR_USER_GROUP")
        d_token = decode_access_token(token)
        # print(d_token)
        decoded_token_json = json.loads(d_token)
        # print(decoded_token_json)
        if decoded_token_json["statusCode"] == 200:
            group_details = json.loads(decoded_token_json["body"])
            # print(group_details)
            if "groups" in group_details:
                groups = group_details["groups"]
                if len(groups) > 0:
                    # check group has been assigned to user or not
                    try:
                        position = groups.index(KEYCLOAK_AYR_USER_GROUP)
                        if position != -1:
                            group_exist = True
                    except ValueError as ve:
                        # print(ve)
                        logging.error("User group : '" + KEYCLOAK_AYR_USER_GROUP
                                      + "' not assigned in keycloak with error :" + str(ve))
                    # print(group_exist)
                else:
                    raise Exception("User do not have any user group assigned in keycloak \n")
            else:
                raise Exception("Failed to extract user group details from access token \n")
        else:
            raise Exception(decoded_token_json["body"])
    except Exception as e:
        # print(e)
        logging.error(e)

    return json.dumps({"statusCode": 200, "body": group_exist})
