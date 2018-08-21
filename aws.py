u""" Provide client interfaces to AWS """
import sys
import boto3
from botocore.exceptions import UnknownServiceError


class AWS:
    """ Class for AWS interactions """
    def __init__(self, profile_name=None):
        self.profile_name = profile_name
        self.session = boto3.session.Session(profile_name=self.profile_name)

    def get_client(self, client_type):
        """ Open a client to an AWS endpoint """
        if not self.session:
            raise KeyError('Cannot open AWS client. I have no session. Open a session first.')
        try:
            return self.session.client(client_type)
        except UnknownServiceError:
            sys.exit('Unknown AWS client type')
