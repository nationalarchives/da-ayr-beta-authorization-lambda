import jwt
import json
import parameter
import logging


def decode_access_token(access_token):
    try:
        aws_environment = parameter.get_parameter_store_key_value("ENVIRONMENT_NAME")
        prefix = "/" + aws_environment + "/"
        KEYCLOAK_CLIENT_ID = parameter.get_parameter_store_key_value(prefix + "KEYCLOAK_CLIENT_ID")
        KEYCLOAK_REALM_PUBLIC_KEY = parameter.get_parameter_store_key_value(prefix + "KEYCLOAK_REALM_PUBLIC_KEY")
        keycloak_public_key = "-----BEGIN PUBLIC KEY-----\n" + KEYCLOAK_REALM_PUBLIC_KEY + "\n-----END PUBLIC KEY-----"

        decoded_token = jwt.decode(access_token, key=keycloak_public_key, algorithms=['RS256'],
                                   audience=KEYCLOAK_CLIENT_ID)
        decode_response = {"statusCode": 200, "body": json.dumps(decoded_token)}
    except Exception as e:
        decode_response = {
            "statusCode": 400,
            "body": "Failed to decode access token : " + str(e)
        }
    return json.dumps(decode_response)


def check_user_group(access_token):
    group_exist = False
    try:
        aws_environment = parameter.get_parameter_store_key_value("ENVIRONMENT_NAME")
        prefix = "/" + aws_environment + "/"
        KEYCLOAK_AYR_USER_GROUP = parameter.get_parameter_store_key_value(prefix + "KEYCLOAK_AYR_USER_GROUP")

        d_token = decode_access_token(access_token)
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
                        logging.error("User group : '" + KEYCLOAK_AYR_USER_GROUP + "' not assigned in keycloak with "
                                                                                   "error :" + str(ve))
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

