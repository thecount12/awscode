"""
Script to move, find, delete, rename, and browse
from dotenv import load_dotenv
load_dotenv(verbose=True)
"""

import boto3
import logging
from datetime import datetime


class BucketManagement(object):
    """
    You will need bucket_data = 'assets-bucket-1qa4znz1qct15'
    prefix = "fdc0cf807b7f/SO_data_collection"
    how to use:
    connect = BucketManagement(bucket_data, log_file="log_delete_files.txt", error_level=WARNING)
    """
    def __init__(self, bucket_data=None, log_file="log_default.log",
                 error_level="INFO", region_name=None,
                 profile_name=None, assume=False, role_arn=None, role_sess_name=None):
        """
        :param bucket_data: str() of buket name
        :param log_file: str() of log file name
        :param error_level: str() of logging error level
        :param region_name: str() of region name
        :param profile_name: str() of profile name dev, prod, grader
        :param assume: bool() of assume role default set to False
        :param role_arn: str() of role name to assume
        :param role_sess_name: st() of session name to use while assume role
        """
        self.bucket_data = bucket_data
        self.region = region_name
        self.profile = profile_name
        self.role = role_arn
        self.role_sess_name = role_sess_name
        session_kwargs = {}
        client_kwargs = {}
        if self.region is not None:
            session_kwargs['region_name'] = self.region
        if self.profile is not None:
            session_kwargs['profile_name'] = self.profile
        session = boto3.Session(**session_kwargs)

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

        self.conn = session.client('s3', **client_kwargs)
        self.s3 = session.resource('s3', **client_kwargs)

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
        self.logger.info(f'Completed configuring logger()!, Time: {datetime.now()}')

    def list_buckets(self):
        """
        List buckets in current account
        :return: list() of bucket names
        """
        bucket_array = []
        for bucket in self.s3.buckets.all():
            #  print(bucket.name)  # for debug only
            bucket_array.append(bucket.name)
        return bucket_array

    def list_objects(self, split=None):
        folder_prefix = []
        key = []
        my_bucket = self.s3.Bucket(self.bucket_data)
        for first_folder in my_bucket.objects.all():
            if split:
                if '/' in first_folder.key:
                    prefix = first_folder.key.split('/')
                    if prefix[0] not in folder_prefix:
                        folder_prefix.append(prefix[0])
            if not split:
                key.append(first_folder.key)
        return key, folder_prefix

    def filter_objects(self, prefix, year, month, day):
        my_bucket = self.s3.Bucket(self.bucket_data)
        for file in my_bucket.objects.filter(Prefix=prefix):
            if file.last_modified.replace(tzinfo=None) < datetime(year, month, day):
                print(f'File Name: {file.key} ---- Date: {file.last_modified}')

    def top_level_folder(self):
        folder = []
        my_bucket = self.s3.Bucket(self.bucket_data)
        result = my_bucket.meta.client.list_objects(Bucket=self.bucket_data, Delimiter='/')
        for item in result.get('CommonPrefixes'):
            #  print(item.get('Prefix'))  # for debug
            folder.append(item.get('Prefix'))
        return folder

    @staticmethod
    def key_dst_fix(key_id, folder, change="", prefix=""):
        """
        :param key_id: str() just the key checksum
        :param folder: str() folder path name
        :param change: str() change to a folder string such as _renamed
        :param prefix: str() of prefix
        :return: str() of new key url location
        """
        folder_strip = folder.replace("/", "")  # removes begin and end of folder str()
        fix_folder = "/" + folder_strip + change
        new_key_path = f"{prefix}{fix_folder}/{key_id}.JPG"
        return new_key_path

    def move_objects(self, src_key, dst_key, move=False):
        """
        :param src_key: str() of source key url
        :param dst_key: str() of destination key url
        :param move: bool() True or False to move files
        :return: None
        """
        copy_source = {
            'Bucket': self.bucket_data,
            'Key': src_key
        }
        print("New file location: {}".format(dst_key))
        bucket = self.s3.Bucket(self.bucket_data)
        self.logger.info('New File location: {}'.format(dst_key))
        if move:
            bucket.copy(copy_source, dst_key)

    def get_key_string(self, prefix="", date="", content="", suffix="", my_hash=""):
        """
        :param prefix: str() of first two levels of key string in s3
        :param date: str() of dates or might be a different name
        :param content: str() of category
        :param suffix: str() or tuple() of suffix like .JPG or .HEIC
        :param my_hash: str() specific hash string to search for
        :return:
        """
        filter_folder = f"{prefix}{date}{content}"
        kwargs = {'Bucket': self.bucket_data}
        if prefix:
            kwargs['Prefix'] = filter_folder

        while True:
            resp = self.conn.list_objects_v2(**kwargs)
            try:
                contents = resp['Contents']
            except KeyError:
                return

            for obj in contents:
                key = obj['Key']
                if key.endswith(suffix) and my_hash in key:
                    yield key
            try:
                kwargs['ContinuationToken'] = resp['NextContinuationToken']
            except KeyError:
                break

    def get_folders(self, prefix="", level="", report=False):
        """
        :param prefix: str() of bucket
        :param level: int() folder level determined by separator /
        :param report: bool()
        :return: folder list()
        """
        folder_list = []
        for lines in self.get_key_string(prefix=prefix):
            folders = lines.split("/")
            if folders[level] in folder_list:  # 2 for out bucket
                pass
            else:
                if report:
                    print(f"found folder: {folders[level]}")
                folder_list.append(folders[level]),
        return folder_list

    def get_hash_only(self, date="", content="", suffix="", my_hash="", hash_path=False, hash_only=False):
        """
        :param date: str() date folder
        :param content: str() content
        :param suffix: str() search for .JPG or .HEIC
        :param my_hash: str() str of hash data
        :param hash_only: bool()
        :param hash_path: bool()
        :return:
        """
        for line in self.get_key_string(date=date, content=content, suffix=suffix, my_hash=my_hash):
            item = line.split("/IMG")
            key_id = item[0][len(item)-34:]  # only get the hash key
            if hash_only:
                print(key_id)  # only get the hash key
                self.logger.info("hash: {}".format(key_id))
            if hash_path:
                print("hash path: {}".format(line))  # debug only
                self.logger.info('hash path: {}'.format(line))

    def delete_object(self, old_key, delete=False):
        """
        :param old_key: str() of key to delete
        :param delete: bool() true or false
        :return: None
        """
        my_delete = self.s3.Object(self.bucket_data, old_key)
        print("Object to delete: {}".format(old_key))
        self.logger.info('Files to delete: {}'.format(old_key))
        if delete:
            my_delete.delete()

    def object_count(self, folder="", content="", suffix="", prefix="", display=False):
        """
        :param folder: str() of folder name
        :param content: str() of key name or another folder
        :param suffix: str() of suffix like .jpg, heic, json etc...
        :param prefix: str() of prefix usually after bucket name
        :param display: bool() to display data for debugging
        :return: tuple() of count  and bytes
        """
        batch = 0
        batch_count = 1000
        num = 0
        total_size = 0
        for item in self.get_key_string(date=folder, content=content, suffix=suffix, prefix=prefix):
            num += 1
            if num == batch_count:
                batch += 1
                batch_count += 1000
            result = f"number: {num}, batch: {batch}, item: {item}"

            data = self.s3.Object(bucket_name=self.bucket_data, key=item)
            # print(data)  # prints object metadata
            # print(data.last_modified)  # metadata from s3.Object API
            total_size += data.content_length
            if display:
                print(result)
        return num, total_size

    def bucket_2_bucket(self, bucket_data, folder_path):
        """
        usage: bring in Session and resource and create a temp object
        usage: do the same for the destination,
        different buckets and different credentials
        old_data = china.bucket_2_bucket(china_bucket_data, i)  # source
        new_data = connect.bucket_2_bucket(bucket_data, prefix + "/" + i)  # destination
        print(new_data)
        new_data.put(Body=old_data.get()['Body'].read())
        :param bucket_data: str() of bucket
        :param folder_path: str() of key
        :return: return object()
        """
        temp_storage = self.s3.Object(bucket_name=bucket_data, key=folder_path)
        return temp_storage

    def get_bucket_policy(self):
        result = self.conn.get_bucket_policy(Bucket=self.bucket_data)
        return result

    def put_bucket_policy(self, bucket_policy):
        result = self.conn.put_bucket_policy(Bucket=self.bucket_data, Policy=bucket_policy)
        return result
