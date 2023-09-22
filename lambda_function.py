import keycloak_token_manager
import json


def lambda_handler(event, context):
    # print(event)
    try:
        if (event.get("Authorization", None)) is not None:
            input_token = event["Authorization"]
        elif (event.get("authorizationToken", None)) is not None:
            input_token = event["authorizationToken"]
        else:
            # return {"statusCode": 401, "body": "Unauthorized"}
            return generate_policy("user", "Deny", event["methodArn"])
        # print(input_token)
        if input_token is not None:
            token = input_token
            # if (event.get('Authorization', None) or event.get('authorizationToken', None)) is not None:
            # token = event['Authorization'] or event['authorizationToken']
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
                            return generate_policy("user", "Allow", event["methodArn"])
                        else:
                            return generate_policy("user", "Deny", event["methodArn"])
                    else:
                        return generate_policy("user", "Deny", event["methodArn"])
                else:
                    return generate_policy("user", "Deny", event["methodArn"])
            else:
                return generate_policy("user", "Deny", event["methodArn"])
        else:
            # return {"statusCode": 401, "body": "Unauthorized"}
            return generate_policy("user", "Deny", event["methodArn"])
    except Exception as ex:
        # return {"statusCode": 401, "body": "Unauthorized"}
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
        "stringKey": "stringval",
        "numberKey": 123,
        "booleanKey": True,
    }

    return auth_response
