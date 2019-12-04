import reset
import unittest
import post_all_data


class TestNegativeReset(unittest.TestCase):
    headers = {'Content-Type': 'application/json', 'Authorization': 'Token 819fc5e38fda4cbc85027cf93e7bb4cb'}
    request_url = "env-5.test.infoblox.com"
    post_all_data.post_data()

    def test_neg_clean_policy_features(self):
        policy_features = ["category_filters", "named_lists",  "access_codes"]
        for eachItem in policy_features:
            self.assertFalse(reset.clean_atcfw_api(eachItem, self.request_url, self.headers))

    def test_neg_clean_bypass_code_features(self):
        bypass_features = ["category_filters", "named_lists"]
        for eachItem in bypass_features:
            self.assertFalse(reset.clean_atcfw_api(eachItem, self.request_url, self.headers))

    def test_neg_clean_atcfw_features(self):
        atcfw_features = ["internal_domain_lists", "network_lists"]
        for eachItem in atcfw_features:
            self.assertFalse(reset.clean_atcfw_api(eachItem, self.request_url, self.headers))

    def test_neg_clean_cdc_flow(self):
        cdc_flow_features = ["sources", "destinations"]
        for eachItem in cdc_flow_features:
            self.assertFalse(reset.clean_cdc_flow(eachItem, self.request_url, self.headers))


if __name__ == '__main__':
    unittest.main()
