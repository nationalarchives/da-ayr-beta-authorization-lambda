# A simple token-based authorizer example to demonstrate how to use an authorization token
# to allow or deny a request. In this example, the caller named 'user' is allowed to invoke
# a request if the client-supplied token value is 'allow'. The caller is not allowed to invoke
# the request if the token value is 'deny'. If the token value is 'unauthorized' or an empty
# string, the authorizer function returns an HTTP 401 status code. For any other token value,
# the authorizer returns an HTTP 500 status code.
# Note that token values are case-sensitive.

import token_validator
import json


def lambda_handler(event, context):
    # print(event)
    try:
        if (event.get("Authorization", None)) is not None:
            input_token = event["Authorization"]
        elif (event.get("authorizationToken", None)) is not None:
            input_token = event["authorizationToken"]
        else:
            return {"statusCode": 401, "body": "Unauthorized"}

        if input_token is not None:
            token = input_token
            # if (event.get('Authorization', None) or event.get('authorizationToken', None)) is not None:
            # token = event['Authorization'] or event['authorizationToken']
            token_response = json.loads(token_validator.validate_access_token(token))

            if token_response["statusCode"] == 200:
                if token_response["isActive"]:
                    return generate_policy("user", "Allow", event["methodArn"])
                else:
                    return generate_policy("user", "Deny", event["methodArn"])
            else:
                return generate_policy("user", "Deny", event["methodArn"])
        else:
            return {"statusCode": 401, "body": "Unauthorized"}
    except:
        return {"statusCode": 401, "body": "Unauthorized"}


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
