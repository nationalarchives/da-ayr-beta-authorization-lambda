import json
import logging
import keycloak
import parameter


def get_aws_environment_prefix():
    return "/" + parameter.get_parameter_store_key_value("ENVIRONMENT_NAME") + "/"


def get_keycloak_openid_object():
    """
    Get Keycloak object based on configuration values.
    :return: Keycloak object.
    """
    try:
        AWS_ENVIRONMENT_PREFIX = get_aws_environment_prefix()
        KEYCLOAK_BASE_URI = parameter.get_parameter_store_key_value(AWS_ENVIRONMENT_PREFIX + "KEYCLOAK_BASE_URI")
        KEYCLOAK_CLIENT_ID = parameter.get_parameter_store_key_value(AWS_ENVIRONMENT_PREFIX + "KEYCLOAK_CLIENT_ID")
        KEYCLOAK_REALM_NAME = parameter.get_parameter_store_key_value(AWS_ENVIRONMENT_PREFIX + "KEYCLOAK_REALM_NAME")
        KEYCLOAK_CLIENT_SECRET = parameter.get_parameter_store_key_value(AWS_ENVIRONMENT_PREFIX
                                                                         + "KEYCLOAK_CLIENT_SECRET")

        keycloak_openid = keycloak.KeycloakOpenID(server_url=KEYCLOAK_BASE_URI,
                                                  client_id=KEYCLOAK_CLIENT_ID,
                                                  realm_name=KEYCLOAK_REALM_NAME,
                                                  client_secret_key=KEYCLOAK_CLIENT_SECRET)
        return keycloak_openid
    except Exception as e:
        logging.error("Error generating keycloak openid object with error : " + str(e))


def get_access_token(username, password, one_time_passcode=0):
    """
    Get an active access token for user from Keycloak.
    :param username: keycloak username.
    :param password: keycloak user password.
    :param one_time_passcode: one time passcode generated from authenticator app.
    :return: an active access token for user from Keycloak.
    """
    try:
        keycloak_openid = get_keycloak_openid_object()
        access_token_response = keycloak_openid.token(username, password, grant_type="password")
        if one_time_passcode > 0:
            access_token_response = keycloak_openid.token(username, password, grant_type="password",
                                                          totp=one_time_passcode)
        access_token_json = json.loads(json.dumps(access_token_response))
        token_response = {"statusCode": 200, "body": access_token_json["access_token"]}
        # return access_token_json["access_token"]
        logging.info("user access token generated successfully : ")
    except Exception as e:
        logging.error("Failed to get access token for user with error : " + str(e))
        token_response = {
            "statusCode": 403,
            "body": "Failed to get access token for user with error : " + str(e),
        }

    return json.dumps(token_response)


def validate_access_token(token):
    """
    Get isActive status of an access token.
    :param token: user access token received from keycloak.
    :return: isActive status of an access token with statuscode.
    """
    validation_response = {}
    try:
        keycloak_openid = get_keycloak_openid_object()
        validate_token_response = keycloak_openid.introspect(token)  # token['access_token'])
        # print(validate_token_response)
        validate_token_json = json.loads(json.dumps(validate_token_response))
        if validate_token_json["active"]:
            validation_response = {
                "statusCode": 200,
                "isActive": validate_token_json["active"],
                "error": "",
            }
        else:
            validation_response = {"statusCode": 403, "isActive": False, "error": ""}

        logging.info("user access token validated successfully")
    except Exception as e:
        logging.error("Failed to validate access token for user with error : " + str(e))

    return json.dumps(validation_response)


def decode_access_token(token):
    """
    Decode an access token.
    :param token: user access token received from keycloak.
    :return: decode access token using algorithm and keycloak public access key.
    """
    try:
        AWS_ENVIRONMENT_PREFIX = get_aws_environment_prefix()
        KEYCLOAK_REALM_PUBLIC_KEY = parameter.get_parameter_store_key_value(AWS_ENVIRONMENT_PREFIX
                                                                            + "KEYCLOAK_REALM_PUBLIC_KEY")
        KEYCLOAK_CLIENT_ID = parameter.get_parameter_store_key_value(AWS_ENVIRONMENT_PREFIX + "KEYCLOAK_CLIENT_ID")

        keycloak_openid = get_keycloak_openid_object()
        keycloak_public_key = ("-----BEGIN PUBLIC KEY-----\n" + KEYCLOAK_REALM_PUBLIC_KEY
                               + "\n-----END PUBLIC KEY-----")
        options = {"verify_signature": False, "verify_aud": False, "verify_exp": True,
                   "audience": KEYCLOAK_CLIENT_ID}
        decoded_token = keycloak_openid.decode_token(token, key=keycloak_public_key, options=options)
        decoded_token_response = {"statusCode": 200, "body": json.dumps(decoded_token)}
        logging.info("user access token decoded successfully")
    except Exception as e:
        logging.error("Failed to decode user access token with error : " + str(e))
        decoded_token_response = {
            "statusCode": 400,
            "body": "Failed to decode access token : " + str(e)
        }
    return json.dumps(decoded_token_response)


def check_user_group(token):
    """
    validate user group.
    :param token: user access token received from keycloak.
    :return: validate user group received in access token from keycloak.
    """
    group_exist = False
    try:
        AWS_ENVIRONMENT_PREFIX = get_aws_environment_prefix()
        KEYCLOAK_AYR_USER_GROUP = parameter.get_parameter_store_key_value(AWS_ENVIRONMENT_PREFIX
                                                                          + "KEYCLOAK_AYR_USER_GROUP")
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
                        # position = groups.index(KEYCLOAK_AYR_USER_GROUP)
                        # if position != -1:
                        for current_group in groups:
                            if str(KEYCLOAK_AYR_USER_GROUP).lower() in current_group.lower():
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
        logging.info("user group check completed successfully")
    except Exception as e:
        # print(e)
        logging.error("Failed to check user group : " + str(e))

    return json.dumps({"statusCode": 200, "body": group_exist})
