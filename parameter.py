import boto3
from botocore.exceptions import ClientError
import logging


def get_parameter_store_key_value(
    key: str, encrypted=True, default_aws_profile=""
) -> str:
    """
    Get string value of `key` in Parameter Store.
    :param key: Name of key whose value will be returned.
    :param encrypted: Whether key is encrypted (boolean).
    :param default_aws_profile: aws_profile used for local and unit testing.
    :return: String value of requested Parameter Store key.
    """
    # use only for local testing
    if default_aws_profile:
        boto3.setup_default_session(profile_name=default_aws_profile)

    ssm_client = boto3.client("ssm")
    try:
        parameter_value = ssm_client.get_parameter(Name=key)["Parameter"]["Value"]
        logging.info("Parameter value retrieved successfully")
        return parameter_value
    except ClientError as e:  # Exception as e:
        logging.error(
            "Failed to get parameter value, Error : %s", e.response["Error"]["Code"]
        )
        return ""
