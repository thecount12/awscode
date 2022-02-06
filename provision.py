"""
Deployment Script to Provision New Cloud Formation Stacks.
"""
from cloudformation import CloudFormation


cloud = CloudFormation(profile='admin', region='us-west-2', assume=True)


def open_template(name):
    with open(name, 'r') as data:
        template = data.read()
        # print(template)  # debug in rio or console
    return template


def validate(path=None, name=None, bypass=False):
    f_path = f"deploy/{path}/{name}.yml"
    cloud.validate_template(template_name=f_path, load_template=open_template(f_path), bypass=bypass)


# ### validate templates
validate(path="role", name="admin-custom-role")
validate(path="s3", name="admin-s3-policy")

# ### Policies before roles
# cloud.deploy_stack(name="admin-s3-policy", path="s3")


# ### let's create a limited administration role
# cloud.deploy_stack(name="admin-custom-role", path="role",
#                    parameters={"AdminS3Policy": "admin-s3-policy"})


# ### SERVICES TO DEPLOY ONLY ONCE
# ### network infrastructure deploy once
validate(path="network", name="network-infra", bypass=True)
# cloud.deploy_stack(name="network-infra", path="network",
#                    parameters={"VpcName": "Yoda"}, validate_ignore=True, raw=True)

# ### deploy Plan9 CPU/Auth Server
validate(path="ec2", name="plan9-cpu-auth", bypass=True)
cloud.deploy_stack(name="plan9-cpu-auth", path="ec2",
                   parameters={"KeyName": "plan9key"}, validate_ignore=True, raw=True)
