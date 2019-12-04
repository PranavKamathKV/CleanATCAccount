import reset
import unittest 


class TestReset(unittest.TestCase):
    headers = {'Content-Type': 'application/json', 'Authorization': 'Token 819fc5e38fda4cbc85027cf93e7bb4cb'}
    request_url = "https://env-5.test.infoblox.com"

    def test_clean_policy_features(self):
        policy_features = ["security_policies", "access_codes", "named_lists", "category_filters"]
        for eachItem in policy_features:
            self.assertTrue(reset.clean_atcfw_api(eachItem, self.request_url, self.headers))

    def test_clean_atcep_features(self):
        atcep_features = ["roaming_device_groups", "roaming_devices"]
        for eachItem in atcep_features:
            self.assertTrue(reset.clean_atcep_api(eachItem, self.request_url, self.headers))

    def test_clean_onprem_features(self):
        onprem_features = ["on_prem_hosts", "update_configs"]
        for eachItem in onprem_features:
            self.assertTrue(reset.clean_onprem_hosts(eachItem, self.request_url, self.headers))

    def test_clean_atcfw_features(self):
        atcfw_features = ["internal_domain_lists", "network_lists", "redirect_page"]
        for eachItem in atcfw_features:
            self.assertTrue(reset.clean_atcfw_api(eachItem, self.request_url, self.headers))

    def test_clean_anycast(self):
        anycast_features = ["ac_configs"]
        for eachItem in anycast_features:
            self.assertTrue(reset.clean_anycast(eachItem, self.request_url, self.headers))

    def test_clean_join_tokens(self):
        self.assertTrue(reset.clean_join_tokens(self.request_url, self.headers))

    def test_clean_notifications(self):
        notification_features = ["user_alerts", "account_alerts"]
        for eachItem in notification_features:
            self.assertTrue(reset.clean_notifications(eachItem, self.request_url, self.headers))

    def test_clean_cdc_flow(self):
        cdc_flow_features = ["flows","sources","destinations", "etls/filters"]
        for eachItem in cdc_flow_features:
            self.assertTrue(reset.clean_cdc_flow(eachItem, self.request_url, self.headers))

    def test_clean_atlas_tags(self):
        self.assertTrue(reset.clean_atlas_tags(self.request_url, self.headers))

    # def test_clean_ipam_dhcp(self):
    #     ipam_dhcp_features = ["/dhcp/fixed_address", "/dhcp/global", "/dhcp/ha_group", "/dhcp/hardware_filter",
    #                           "/dhcp/option_code", "/dhcp/option_filter",
    #                           "/dhcp/option_group", "/dhcp/option_space", "/dhcp/server", "/ipam/address",
    #                           "/ipam/address_block", "/ipam/host", "/ipam/ip_space", "/ipam/range", "/ipam/subnet"]
    #     for eachItem in ipam_dhcp_features:
    #         self.assertTrue(reset.clean_ipam_dhcp(eachItem, self.request_url, self.headers))


if __name__ == '__main__':
    unittest.main()
