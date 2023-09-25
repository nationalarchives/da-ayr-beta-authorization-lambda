import keycloak_token_manager
import json
import logging


def lambda_handler(event, context):
    """
    return authorization of user.
    :param event: lambda handler event.
    :param context: lambda handler context.
    :return: authorize user based on access token and key cloak group assigned.
    """
    # print(event)
    # default access level set to not allowed
    allowed_access = False
    try:
        input_token = ""
        if (event.get("Authorization", None)) is not None:
            input_token = event["Authorization"]
        elif (event.get("authorizationToken", None)) is not None:
            input_token = event["authorizationToken"]
        # print(input_token)

        if input_token is not None:
            token = input_token
            token_response = json.loads(keycloak_token_manager.validate_access_token(token))
            # print(token_response)
            if token_response["statusCode"] == 200:
                if token_response["isActive"]:
                    # validate if user has a valid user group link to ayr
                    group_check_response = json.loads(keycloak_token_manager.check_user_group(token))
                    if group_check_response["statusCode"] == 200:
                        group_exist = group_check_response["body"]
                        # print(group_exist)
                        if group_exist:
                            allowed_access = True

        logging.info("User authorized successfully")
    except Exception as e:
        logging.error("Failed to authorize the user : " + str(e))
    finally:
        logging.info("User authorization process completed successfully")
        if allowed_access:
            return generate_policy("user", "Allow", event["methodArn"])
        else:
            return generate_policy("user", "Deny", event["methodArn"])


def generate_policy(principal_id, effect, resource):
    auth_response = {"principalId": principal_id}

    if effect and resource:
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "execute-api:Invoke", "Effect": effect, "Resource": resource}
            ],
        }
        auth_response["policyDocument"] = policy_document

    auth_response["context"] = {
        "stringKey": "test string",
        "numberKey": 123,
        "booleanKey": True,
    }

    return auth_response
