"""
Script to create stacks for Roles and Policies
requires:
pip3 install boto3
"""

import sys
import logging
import json
import boto3
import botocore
import botocore.exceptions
import botocore.errorfactory


class CloudFormation(object):
    """
    You need to know AWS profile:
    usage:
    cloud = CloudFormation(profile='prod', region='us-west-2')
    cloud.deploy_stack(name="druid-CBM-access-role", path="role",
                       parameters={"DruidS3Policy": "druid-s3-policy",
                                   "DruidSQSPolicy": "druid-sqs-policy"
                                   })

    """

    def __init__(self, profile=None, region=None,
                 log_file="log_default.log", error_level="INFO",
                 assume=False, role_arn=None, role_sess_name=None):
        """
        Most are default but if you need to assume a role you might need to add profile, and region
        for the account you are starting out in. Then set assume to True and pick the role name you plan
        to assume and a session name.
        :param profile: str() of profile name -> prod, dev, grader etc.
        :param region: str() of region_name 'us-west-2'.
        :param log_file: str() of log_file name.
        :param error_level: str() of logger error level.
        :param assume: bool() default to false.
        :param role_arn: str() of role arn ex: arn:aws:iam::account-of-role-to-assume:role/name-of-role
        :param role_sess_name: str() of session role name. Should be unique for each job
        """
        self.profile = profile
        self.region = region
        self.role = role_arn
        self.role_sess_name = role_sess_name
        session_kwargs = {}
        client_kwargs = {}
        if self.region is not None:
            session_kwargs['region_name'] = self.region
        if self.profile is not None:
            session_kwargs['profile_name'] = self.profile
        session = boto3.session.Session(**session_kwargs)

        if assume:
            sts_client = session.client('sts')
            assumed_role_object = sts_client.assume_role(
                RoleArn=self.role,
                RoleSessionName=self.role_sess_name
            )
            credentials = assumed_role_object['Credentials']
            client_kwargs['aws_access_key_id'] = credentials['AccessKeyId']
            client_kwargs['aws_secret_access_key'] = credentials['SecretAccessKey']
            client_kwargs['aws_session_token'] = credentials['SessionToken']

        self.client_iam = session.client('iam', **client_kwargs)
        self.client_cloud = session.client('cloudformation', **client_kwargs)
        self.client_rds = session.client('rds', **client_kwargs)
        self.client_ec2 = session.client('ec2', **client_kwargs)
        self.client_s3 = session.client('s3', **client_kwargs)
        self.client_kms = session.client('kms', **client_kwargs)

        self.log_file = log_file
        self.level = error_level

        # Create the Logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(self.level)

        # Create the Handler for logging data to a file
        logger_handler = logging.FileHandler(self.log_file)
        logger_handler.setLevel(self.level)

        # Create a Formatter for formatting the log messages
        logger_formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')

        # Add the Formatter to the Handler
        logger_handler.setFormatter(logger_formatter)

        # Add the Handler to the Logger
        self.logger.addHandler(logger_handler)
        self.logger.info(f'Completed config')

    @staticmethod
    def __open_template(name):
        """
        path to name of file might be different in rio
        ex: 'deploy/role/druid-will_test.yml'
        :param name: str() of file name and its path
        :return: str()
        """
        with open(name, 'r') as data:
            template = data.read()
            # print(template)  # debug in rio or console
        return template

    @staticmethod
    def params(**kwargs):
        """
        Usage: params(ParameterKey='Name_add_2_policy_parm', ParameterValue='Value_add_2_policy_parm)
        The keys must always be the same, cloud formation takes it as a list of dictionary
        :param kwargs: dict() input values
        :return: dict()
        """
        return kwargs

    def get_policy_arn(self, policy_name):
        """
        get policy arn from policy_name prefix
        :param policy_name: str() of policy name without hash
        :return: str() or arn or not found
        """
        marker = None
        while True:
            if marker:
                response_iterator = self.client_iam.list_policies(
                    Marker=marker,
                    MaxItems=10,
                    Scope='Local',
                    PolicyUsageFilter='PermissionsPolicy',
                )
            else:
                response_iterator = self.client_iam.list_policies(
                    MaxItems=10,
                    Scope='Local',
                    PolicyUsageFilter='PermissionsPolicy',
                )
            data_list = response_iterator['Policies']
            for item in data_list:
                if policy_name in item['Arn']:
                    return item['Arn']
            try:
                marker = response_iterator['Marker']
            except KeyError:
                break

    def get_role(self, role_name, all=False):
        """
        get role name from iam list that has proper hash
        :param role_name: str() of role_name to find that contains a hash
        :param all: boolean
        :return: str() of roles full name with hash
        """
        marker = None
        while True:
            if marker:
                response_iterator = self.client_iam.list_roles(
                    Marker=marker,
                    MaxItems=10
                )
            else:
                response_iterator = self.client_iam.list_roles(
                    MaxItems=10
                )
            data_list = response_iterator['Roles']
            for item in data_list:
                if all:
                    if role_name in item['RoleName']:
                        return item
                else:
                    if role_name in item['RoleName']:
                        return item['RoleName']
            try:
                marker = response_iterator['Marker']
                # print(marker)  # prints marker token debug only
            except KeyError:
                break

    def get_stack_list(self, stack_name=None):
        """
        Get list of current stats and the summary. This is useful if cloudformation is taking a long time, and you
        want to wait for stack to complete before attaching or creating another resource
        :param stack_name: str() of stack name optional
        :return: list()
        """
        next_token = None
        stack_list = []
        while True:
            if next_token:
                response_iterator = self.client_cloud .list_stacks(NextToken=next_token)
            else:
                response_iterator = self.client_cloud .list_stacks()
            data_list = response_iterator["StackSummaries"]
            for item in data_list:
                if stack_name:
                    if stack_name in item["StackName"]:
                        print(item)
                        stack_list.append(item)
                else:
                    print(item)  # list all stacks
            try:
                next_token = response_iterator["NextToken"]
                # print(f"debug:: {next_token}")
            except KeyError:
                break
        return stack_list

    def rds_info(self, db_name):
        """
        Using stack name you can extract detail information such as VPC Security Group, and port
        :param db_name: str() of rds stack name or database name
        :return: tuple(security, port)
        """
        marker = None
        while True:
            if marker:
                response_iterator = self.client_rds.describe_db_instances(
                    Marker=marker,
                    MaxRecords=20
                )
            else:
                response_iterator = self.client_rds.describe_db_instances(
                    MaxRecords=20
                )
            data_list = response_iterator['DBInstances']
            security_list = []
            for item in data_list:
                if db_name in item['DBInstanceIdentifier']:
                    # pprint.pprint(item)  # debug only
                    security_group = item['VpcSecurityGroups']
                    security_list.append(security_group[-1]['VpcSecurityGroupId'])  # last in list
                    print(f"Working on RDS: {item['Endpoint']['Address']}")  # for logs only
                    security_list.append(item['Endpoint']["Port"])
                    return tuple(security_list)
            try:
                marker = response_iterator['Marker']
                # print(marker)  # prints marker token debug only
            except KeyError:
                break

    def get_ec2_network(self, security):
        """
        Everything is an EC2 including rds deployment. This tool is helpful to find IP address of primary
        and secondary RDS endpoints
        :param security: str() of security group id
        :return: None
        """
        next_token = None
        ip_list = []
        while True:
            if next_token:
                response_iterator = self.client_ec2.describe_network_interfaces(
                    MaxResults=100,
                    NextToken=next_token
                )
            else:
                response_iterator = self.client_ec2.describe_network_interfaces(
                    MaxResults=100
                )
            data_list = response_iterator["NetworkInterfaces"]
            for item in data_list:
                if security in str(item["Groups"]):  # this could be a list, easier to convert to string
                    print(f"IP stuff: {item['PrivateIpAddress']}")
                    ip_list.append(item['PrivateIpAddress'])
            try:
                next_token = response_iterator["NextToken"]
                # print(f"debug:: {next_token}")  # for debug only
            except KeyError:
                break
        return ip_list

    def validate_template(self, template_name, load_template, bypass=None):
        """
        Use this to test out templates before cloud formation deployment
        :param template_name: str() of path to template name to load
        :param load_template: str() of template body loaded from open_template()
        :param bypass: boolean
        :return: dict() or None
        """
        try:
            response = self.client_cloud.validate_template(TemplateBody=load_template)
            if bypass:
                return None
            if response['Capabilities'] == ['CAPABILITY_IAM']:
                print(f"Template Clean: {template_name}")
                return response
        except Exception as template_error:
            print(f"ERROR: Fix me please ----------v\n{template_error}")
            sys.exit(1)  # break out of rio

    def create_stack(self, stack_name, template, parm=None, capabilities=None):
        """
        Create cloud formation stack
        most of the time we use 'CAPABILITY_IAM'
        :param stack_name: str()
        :param template: str() of cloud formation file open_template()
        :param parm: list() of dict() of parameters
        :param capabilities: list() of capabilities
        :return: dict() of response
        """
        response = self.client_cloud.create_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=parm,
            Capabilities=capabilities,
            Tags=[
                {
                    'Key': 'AIS-REQ-1=ISDB-Service-ID',
                    'Value': 'e45ef9c2-92f9-4ac5-97ea-6eae001b5803:Env=1'
                },
                ],
            )
        return response

    def update_stack(self, stack_name, template, parm=None, capabilities=None):
        """
        deploy the cloud formation stack or do an update
        :param stack_name: str()
        :param template: str() of cloud formation file open_template()
        :param parm: list() of dict() of parameters
        :param capabilities: list() of capabilities
        :return: dict() of response
        """
        response = self.client_cloud.update_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=parm,
            Capabilities=capabilities,
            Tags=[
                {
                    'Key': 'AIS-REQ-1=ISDB-Service-ID',
                    'Value': 'e45ef9c2-92f9-4ac5-97ea-6eae001b5803:Env=1'
                },
                ],
            )
        return response

    def deploy_stack(self, name, path, parameters=None, raw=False, validate_ignore=False, capabilities=None):
        """
        Deploy a new stack. Consider this main for 90% of druid work
        :param name: str() of name of file without extension
        :param path: str() of sub-folder ex: '/deploy/path/name'
        :param parameters: dict() key value pairs to be entered into Parameters of stack
        :param raw: bool() raw fields don't require arn
        :param validate_ignore: bool() by pass validate template
        :param capabilities: list() of capabilities
        if parameters is not None chances are it's a role and will require the full arn using get_policy_arn()
        :return:
        """
        if capabilities is None:
            capabilities = ["CAPABILITY_IAM"]
        file_path = f'deploy/{path}/{name}.yml'
        print(f'inside create for {file_path}')
        self.validate_template(template_name=file_path,
                               load_template=self.__open_template(file_path),
                               bypass=validate_ignore)
        params_list = []
        params_list.append(self.params(ParameterKey='OutputName', ParameterValue=name))
        if parameters:
            for key, val in parameters.items():
                data_val = self.get_policy_arn(val)
                if raw:
                    data_val = val
                if data_val is None:
                    print("Could not find Policy ARN. Make sure name is correct")
                    sys.exit(1)
                print(f"key: {key}, val: {data_val}")
                params_list.append(self.params(ParameterKey=key, ParameterValue=data_val))
        print(params_list)  # for debug only
        try:
            results = self.create_stack(stack_name=name, template=self.__open_template(file_path),
                                        parm=params_list, capabilities=capabilities)
            print(results)  # aws dict of stack
        except botocore.errorfactory.ClientError as error:
            # print(error)
            if error.response['Error']['Code'] == 'AlreadyExistsException':
                print("Policy or Role exists: Lets update")  # maybe update chain
                try:
                    update = self.update_stack(stack_name=name, template=self.__open_template(file_path),
                                               parm=params_list, capabilities=capabilities)
                    print(update)  # aws dict of stack
                except botocore.errorfactory.ClientError as update_error:
                    # print(update_error)
                    if update_error.response['Error']['Code'] == 'ValidationError':
                        print(f"No updates are to be performed: No changes")
                    else:
                        print(f"Unexpected error: {update_error}")
            else:
                print(f"CLIENT Unexpected error: {error}")
                sys.exit(1)  # break out of rio

    def destroy(self, stack_name):
        """
        Sometimes you have to wait 3 hours for a stack to get destroyed if its hung. Let's force destruction
        :param stack_name: str() of stack name
        :return: dict()
        """
        response = self.client_cloud.delete_stack(
            StackName=stack_name)
        return response

    def update_policies(self, items, path):
        """
        This is just a fancy list. Over time new policies and roles can get extremely large. In provision.py you
        can import another python file that is a group of large lists
        Example usage:
        import large_list.py  # ex: vars.py
        cloud.update_policies(glue_policies, 'glue')
        :param items: list() of names from vars.py
        :param path: str() of policy type - s3, glue, athena
        """
        for x in items:
            print(f"{x}, {path}")  # debug only
            self.deploy_stack(name=x, path=path)

    def kms_key(self, bucket):
        """
        Get encryption KMS KeyID using buket name
        :param bucket: str()
        :return: str()
        """
        try:
            response = self.client_s3.get_bucket_encryption(
                Bucket=bucket
            )
            server_enc_config = 'ServerSideEncryptionConfiguration'
            apply_enc_default = 'ApplyServerSideEncryptionByDefault'
            server_side = response[server_enc_config]['Rules'][-1][apply_enc_default]['KMSMasterKeyID']
            return server_side
        except Exception as bucket_error:
            print(bucket_error)

    def kms_put_policy(self, key, policy):
        """
        Requires UUID of key string and payload
        :param key: str() of key uuid
        :param policy: str() of payload, should be multiple lines
        :return: str()
        """
        try:
            response = self.client_kms.put_key_policy(
                KeyId=key,
                PolicyName='default',
                Policy=policy,
            )
            return response
        except Exception as put_error:
            return put_error

    def get_role_arn(self, role):
        """
        This needs roles proper arn name with hash: It fails on new roles if not enough time is given. It takes
        for new roles to be created in cloudformation. This is tech debt. I don't want sleeps on every push only
        on the first new role that is created
        :param role: str() from role_arg
        :return: str() of arn or Role not found
        """
        try:
            print("search role ARN")
            get_role_arn = self.client_cloud.get_role(
                RoleName=role
            )
            return get_role_arn['Role']['Arn']
        except Exception as role_err:
            print(role_err)
            return 'Role not found'

    def kms_policy_main(self, key, role):
        """
        Appending the new role to the policy. This requires the key_id str()
        :param key: str()
        :param role: str() of role name
        :return: Null
        """
        key_id = key.split("/")  # we want UUI / :1
        try:
            response = self.client_kms.get_key_policy(
                KeyId=key_id[1],
                PolicyName='default'
            )
            policy = json.loads(response['Policy'])  # convert to dict
            arn_roles = policy['Statement'][-1]['Principal']['AWS']  # list of ARN's
            if any(role in x for x in arn_roles):
                match = [x for x in arn_roles if role in x]
                print(f"This role already exists: {match[-1]}")
            else:
                arn_roles.append(self.get_role_arn(role))  # get_role_arn(role)
                policy['Statement'][-1]['Principal']['AWS'] = arn_roles  # update dict with new list
                json_policy = json.dumps(policy)  # convert to string
                print(self, self.kms_put_policy(key_id[1], json_policy))  # Add new role_arn to policy arn
        except Exception as get_key_policy_error:
            print(get_key_policy_error)

    def kms_changes(self, bucket_names=None, role_name=None):
        """
        Apply the KMS changes. All this is doing is adding role_name_hash to bucket kms policy.
        If an error occurs you can easily log in and fix it in both buckets listed below.
        :param bucket_names: list of buckets to add roles to kms policy
        :param role_name: str() of role_name without hash
        :return: Null
        """
        if bucket_names is None:
            bucket_names = ['druid-users', 'aimla9ops-data']
        for item in bucket_names:
            self.kms_policy_main(self.kms_key(item), role=role_name)
