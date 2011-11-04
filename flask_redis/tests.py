import unittest
import application
from utils import aws, config
from utils.exceptions import AWSError, ConfigError
import settings
import logging

TEST_ORGANIZATION = 'default'

class CoreTestCase(unittest.TestCase):
    def setUp(self):
        self.client = application.app.test_client()

    def test_index(self):
        resp = self.client.get('/')
        assert(resp.status_code == 200)

    def tearDown(self):
        pass

class ConfigTestCase(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass

    def test_get_org_config(self):
        self.assertRaises(ConfigError, config.get_org_config)
        cfg = config.get_org_config(TEST_ORGANIZATION)
        assert 'aws_access_id' in cfg
        assert 'aws_secret_key' in cfg
        assert 'aws_account_id' in cfg
        assert 'api_keys' in cfg
        assert 'ssh_key' in cfg
        assert 'puppet_ip' in cfg
        assert 'puppet_host' in cfg
        assert 'security_groups' in cfg
        assert 'www_server_name' in cfg


class AwsTestCase(unittest.TestCase):
    def setUp(self):
        self.config = config.get_org_config(TEST_ORGANIZATION)
        pass

    def tearDown(self):
        pass

    def test_get_ec2_connection(self):
        conn = aws.get_ec2_connection(organization=TEST_ORGANIZATION)
        assert conn != None
        conn = aws.get_ec2_connection('us-west-1', organization=TEST_ORGANIZATION)
        assert conn != None
        assert conn.region.name.lower() == 'us-west-1'

    def test_get_ami_id(self):
        assert aws.get_ami_id('CORE', 'dev', 'us-east-1', organization=TEST_ORGANIZATION) != None

    def test_check_keypair(self):
        assert aws.check_keypair(self.config['ssh_key'], 'us-east-1', organization=TEST_ORGANIZATION) == True
        assert aws.check_keypair(self.config['ssh_key'], 'us-west-1', organization=TEST_ORGANIZATION) == True

    def test_check_security_groups(self):
        assert aws.check_security_groups('us-east-1', organization=TEST_ORGANIZATION) == True
        assert aws.check_security_groups('us-west-1', organization=TEST_ORGANIZATION) == True

    def test_get_region_name(self):
        self.assertRaises(AWSError, aws.get_region_name)
        assert aws.get_region_name('us-east-1c') == 'us-east-1'

    def test_launch_instance(self):
        instance_id = aws.launch_instance(self.config['alestic_ami_id_us_east'], zone='us-east-1c', \
            organization=TEST_ORGANIZATION)
        assert instance_id != None
        aws.terminate_instance(instance_id, 'us-east-1', organization=TEST_ORGANIZATION)

    def test_launch_puppet_instance(self):
        res = aws.launch_puppet_instance('test', 'dev', zone='us-east-1c', sync=False, \
            organization=TEST_ORGANIZATION)
        assert res['instance_id'] != None
        aws.terminate_instance(res['instance_id'], 'us-east-1', organization=TEST_ORGANIZATION)

if __name__=="__main__":
    core_suite = unittest.TestLoader().loadTestsFromTestCase(CoreTestCase)
    config_suite = unittest.TestLoader().loadTestsFromTestCase(ConfigTestCase)
    print("""    Not running the AWS tests.  To test, make sure a valid config_local.json file exists,\n"""\
        """    and edit TEST_ORGANIZATION in tests.py to use the specified organization.  Then run\n"""\
        """    python -m unittest -v tests.AwsTestCase \n"""
    )

    all_tests = unittest.TestSuite([core_suite, config_suite])
    unittest.TextTestRunner(verbosity=2).run(all_tests)
