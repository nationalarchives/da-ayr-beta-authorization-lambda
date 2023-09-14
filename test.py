import unittest
import json

import parameter
import token_generator
import token_validator
import lambda_function

# set config environment for testing
aws_profile = "tna-ayr-sandbox"
test_keycloak_username = parameter.get_parameter_store_key_value(
    "KEYCLOAK_TEST_USER", encrypted=False, default_aws_profile=aws_profile
)
test_keycloak_password = parameter.get_parameter_store_key_value(
    "KEYCLOAK_TEST_USER_PASSWORD", encrypted=False, default_aws_profile=aws_profile
)


# run following command to perform unit testing on all test cases
# python3 -m unittest test


class TestParameter(unittest.TestCase):
    def test_get_parameter_value_with_valid_key(self):
        """
        Test that it can return parameter value
        :return: parameter value
        """
        key = "KEYCLOAK_BASE_URI"
        result = parameter.get_parameter_store_key_value(
            key, encrypted=False, default_aws_profile=aws_profile
        )
        self.assertEqual(result, "https://auth.tdr-integration.nationalarchives.gov.uk")

    def test_get_parameter_value_with_invalid_key(self):
        """
        Test that it can return parameter value
        :return: ""
        """
        key = "KEYCLOAK_BASE_URI_NOT"  # invalid key
        result = parameter.get_parameter_store_key_value(
            key, encrypted=False, default_aws_profile=aws_profile
        )
        self.assertEqual(result, "")


class TestTokenGenerator(unittest.TestCase):
    def test_get_access_token_with_valid_user_details(self):
        """
        get access token from keycloak
        :return:
        """
        username = test_keycloak_username
        password = test_keycloak_password
        result = json.loads(token_generator.get_access_token(username, password))
        self.assertEqual(result["statusCode"], 200)

    def test_get_access_token_with_invalid_user_details(self):
        """
        get access token from keycloak
        :return:
        """
        username = test_keycloak_username
        password = "test"
        result = json.loads(token_generator.get_access_token(username, password))
        self.assertEqual(result["statusCode"], 403)

    def test_get_access_token_with_empty_user_details(self):
        """
        get access token from keycloak
        :return:
        """
        username = ""
        password = ""
        result = json.loads(token_generator.get_access_token(username, password))
        self.assertEqual(result["statusCode"], 403)


class TestTokenValidator(unittest.TestCase):
    def test_validate_access_token_with_active_valid_token(self):
        """
        Test that it toke is active
        :return:
        """
        # get token
        username = test_keycloak_username
        password = test_keycloak_password
        token_response = json.loads(
            token_generator.get_access_token(username, password)
        )
        token = token_response["body"]
        result = json.loads(token_validator.validate_access_token(token))
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(result["isActive"], True)
        self.assertEqual(result["error"], "")

    def test_validate_access_token_with_inactive_invalid_token(self):
        """
        Test that it can return parameter value
        :return:
        """
        # using invalid token
        token = "test_token"  # invalid token
        result = json.loads(token_validator.validate_access_token(token))
        self.assertEqual(result["statusCode"], 403)
        self.assertEqual(result["isActive"], False)
        self.assertEqual(result["error"], "")

    def test_validate_access_token_for_exception(self):
        """
        Test that it can return parameter value
        :return:
        """
        # using invalid token
        token = ""
        result = json.loads(token_validator.validate_access_token(token))
        self.assertEqual(result["statusCode"], 403)
        self.assertEqual(result["isActive"], False)
        self.assertEqual(result["error"], "")


class TestLambdaFunction(unittest.TestCase):
    def test_lambda_function_with_authorization_parameter_access_allow_response_using_valid_token(
        self,
    ):
        """
        Check token is valid and active
        :return:
        """
        username = test_keycloak_username
        password = test_keycloak_password
        token_response = json.loads(
            token_generator.get_access_token(username, password)
        )
        token = token_response["body"]

        lambda_event = {"methodArn": "*", "Authorization": token}
        result = json.loads(
            json.dumps(lambda_function.lambda_handler(event=lambda_event, context=""))
        )
        self.assertEqual(result["policyDocument"]["Statement"][0]["Effect"], "Allow")

    def test_lambda_function_with_authorizationToken_parameter_access_allow_response_using_valid_token(
        self,
    ):
        """
        Check token is valid and active
        :return:
        """
        username = test_keycloak_username
        password = test_keycloak_password
        token_response = json.loads(
            token_generator.get_access_token(username, password)
        )
        token = token_response["body"]

        lambda_event = {"methodArn": "*", "authorizationToken": token}
        result = json.loads(
            json.dumps(lambda_function.lambda_handler(event=lambda_event, context=""))
        )
        self.assertEqual(result["policyDocument"]["Statement"][0]["Effect"], "Allow")

    def test_lambda_function_with_authorization_parameter_access_deny_response_using_invalid_token(
        self,
    ):
        """
        Check token is valid but not active
        :return:
        """
        lambda_event = {
            "methodArn": "*",
            "Authorization": "test_token",
        }
        result = json.loads(
            json.dumps(lambda_function.lambda_handler(event=lambda_event, context=""))
        )
        self.assertEqual(result["policyDocument"]["Statement"][0]["Effect"], "Deny")

    def test_lambda_function_with_authorizationToken_parameter_access_deny_response_using_invalid_token(
        self,
    ):
        """
        Check token is valid but not active
        :return:
        """
        lambda_event = {
            "methodArn": "*",
            "authorizationToken": "test_token",
        }
        result = json.loads(
            json.dumps(lambda_function.lambda_handler(event=lambda_event, context=""))
        )
        self.assertEqual(result["policyDocument"]["Statement"][0]["Effect"], "Deny")

    def test_lambda_function_with_authorization_parameter_access_deny_response_using_empty_token(
        self,
    ):
        """
        Check token response using empty Authorization parameter
        :return:
        """
        lambda_event = {"methodArn": "*", "Authorization": ""}
        result = json.loads(
            json.dumps(lambda_function.lambda_handler(event=lambda_event, context=""))
        )
        # self.assertEqual(result['statusCode'], 401)
        # self.assertEqual(result['body'], 'Unauthorized')
        self.assertEqual(result["policyDocument"]["Statement"][0]["Effect"], "Deny")

    def test_lambda_function_with_authorizationToken_parameter_access_deny_response_using_empty_token(
        self,
    ):
        """
        Check token response using empty Authorization parameter
        :return:
        """
        lambda_event = {"methodArn": "*", "authorizationToken": ""}
        result = json.loads(
            json.dumps(lambda_function.lambda_handler(event=lambda_event, context=""))
        )
        # self.assertEqual(result['statusCode'], 401)
        # self.assertEqual(result['body'], 'Unauthorized')
        self.assertEqual(result["policyDocument"]["Statement"][0]["Effect"], "Deny")

    def test_lambda_function_failed_response_with_no_token(self):
        """
        Check token response using missing Authorization parameter
        :return:
        """
        lambda_event = {
            "methodArn": "*",
            # 'Authorization': ''
        }
        result = json.loads(
            json.dumps(lambda_function.lambda_handler(event=lambda_event, context=""))
        )
        self.assertEqual(result["statusCode"], 401)
        self.assertEqual(result["body"], "Unauthorized")


if __name__ == "__main__":
    unittest.main()
