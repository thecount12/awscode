"""
script to tear down services
"""

from cloudformation import CloudFormation

cloud = CloudFormation(profile='prod', region='us-west-2')

# cloud.destroy(stack_name="plan9-cpu-auth")