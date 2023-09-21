import traceback
import boto3
import jwt
import json
import parameter
import token_generator

aws_profile = "tna-ayr-sandbox"
if aws_profile:
    boto3.setup_default_session(profile_name=aws_profile)


def decode_access_token(token):
    try:
        aws_environment = parameter.get_parameter_store_key_value("ENVIRONMENT_NAME", encrypted=False,
                                                                  default_aws_profile=aws_profile)
        prefix = "/" + aws_environment + "/"
        KEYCLOAK_CLIENT_ID = parameter.get_parameter_store_key_value(prefix + "KEYCLOAK_CLIENT_ID",
                                                                     encrypted=False,
                                                                     default_aws_profile=aws_profile)

        KEYCLOAK_REALM_PUBLIC_KEY = parameter.get_parameter_store_key_value(prefix + "KEYCLOAK_REALM_PUBLIC_KEY",
                                                                            encrypted=False,
                                                                            default_aws_profile=aws_profile)
        keycloak_public_key = "-----BEGIN PUBLIC KEY-----\n" + KEYCLOAK_REALM_PUBLIC_KEY + "\n-----END PUBLIC KEY-----"

        decoded_token = jwt.decode(token, key=keycloak_public_key, algorithms=['RS256'], audience=KEYCLOAK_CLIENT_ID)
        # return json.dumps(decoded_token)
        decode_response = {"statusCode": 200, "body": json.dumps(decoded_token)}
    except Exception as e:
        # print(traceback.print_exc())
        decode_response = {
            "statusCode": 400,
            "body": "Failed to decode access token : " + str(e)
        }
    return json.dumps(decode_response)


def get_user_group_policies(group_name):
    try:
        client = boto3.client('iam')
        policy_names = []
        # This is for AWS managed policies and returns both the policy ARN and name
        attached_group_policies = (client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies'])
        for policy in attached_group_policies:
            policy_names.append(policy['PolicyName'])
        # This is for inline policies and returns only the policy name
        group_policies = (client.list_group_policies(GroupName=group_name)['PolicyNames'])
        for policy in group_policies:
            policy_names.append(policy)
        # return policy_names
        group_policy_response = {"statusCode": 200, "body": policy_names}
    except Exception as ex:
        # print(ex)
        group_policy_response = {"statusCode": 400, "body": str(ex)}
    return json.dumps(group_policy_response)


def get_user_groups(username, password):
    try:
        token = token_generator.get_access_token(username, password)
        # print(token)
        token_json = json.loads(token)
        if token_json["statusCode"] == 200:
            access_token = (json.loads(token))["body"]
            # print(access_token)
            d_token = decode_access_token(access_token)
            # print(d_token)
            decoded_token_json = json.loads(d_token)
            # print(decoded_token_json)
            if decoded_token_json["statusCode"] == 200:
                group_details = json.loads(decoded_token_json["body"])
                # print(groups)
                if "groups" in group_details:
                    groups = group_details["groups"]
                    print("List of user group(s) and policies assigned to user : '" + username + "'\n")
                    if len(groups) > 0:
                        counter = 1
                        for user_group in groups:
                            user_group_name = user_group  # .replace("/", "").strip()
                            print("User Group " + str(counter) + " : " + user_group_name)
                            user_group_policy_json = json.loads(get_user_group_policies(user_group_name))
                            if user_group_policy_json["statusCode"] == 200:
                                user_group_policies = user_group_policy_json["body"]
                                # print("The user group : '" + user_group_name +
                                #      "' has following policies applied to it: \n")
                                # print(user_group_policies)
                                print("Policies applied : " + str(user_group_policies) + "\n")
                            else:
                                # user_group_policy_json["body"]
                                raise Exception("The user group : '" + user_group_name +
                                                "' do not have any policy/policies assigned to it \n")
                            counter += 1
                    else:
                        raise Exception("User do not have any user group assigned in keycloak \n")
                else:
                    raise Exception("Failed to extract user group details from access token \n")
            else:
                raise Exception(decoded_token_json["body"])  # "Failed to decode access token")
        else:
            raise Exception(token_json["body"])  # "Failed to receive access token from Keycloak")
    except Exception as e:
        print(e)


if __name__ == "__main__":
    # get_user_groups("tdr-admin@testsomething.com", "L0gitech")
    # one valid user group assigned - linked to AWS user group
    get_user_groups("tdr-user1@testsomething.com", "L0gitech")
    # valid user group assigned - not linked to AWS user groups
    get_user_groups("tdr-user2@testsomething.com", "L0gitech")
    # multiple valid user group assigned - linked to AWS user groups
    get_user_groups("tdr-user3@testsomething.com", "L0gitech")
    # multiple valid user group assigned - linked to AWS user groups except one user group
    get_user_groups("tdr-user4@testsomething.com", "L0gitech")
