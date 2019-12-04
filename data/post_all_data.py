#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import requests
import random
import string
import reset

data = {}
TIMEOUT = 5


# Cleans ATCFW API objects
def post_data():
    request_url = "https://env-5.test.infoblox.com"
    headers = {'Content-Type': 'application/json', 'Authorization': "Token 819fc5e38fda4cbc85027cf93e7bb4cb"}
#819fc5e38fda4cbc85027cf93e7bb4cb
# c50fdc9083c1feae39978f77aa124df9

    # Create Category Filters
    print("Creating the Category Filters")
    if not create_category_filter(request_url, headers, "category_filters"):
        print("Failed to create category Filters")
        return False

    # Create Custom Lists
    print("Creating the Custom Lists")
    if not create_custom_lists(request_url, headers, "named_lists"):
        print("Failed to create the custom lists")
        return False

    # Create Access Codes
    print("Creating the Bypass Codes")
    if not create_bypass_codes(request_url, headers, "access_codes"):
        print("Failed to create the bypass codes")
        return False

    # Create Security Policies
    print("Creating the security policies")
    if not create_policy_data(request_url, headers, "security_policies"):
        print("Failed to create the security policies")
        return False

    # Create Internal Domains
    print("Creating the internal domain lists")
    if not create_internal_domains(request_url, headers, "internal_domain_lists"):
        print("Failed to create the internal domain lists")
        return False

    # Create Network Lists
    print("Creating the Network lists")
    if not create_network_lists(request_url, headers, "network_lists"):
        print("Failed to create the network lists")
        # return False

    # Create Redirect Page
    print("Creating the Redirect Page")
    if not create_redirect_page(request_url, headers, "redirect_page"):
        print("Failed to create the redirect page")
        return False

    # Create Roaming Devices
    print("Creating the Roaming Devices")
    if not create_dummy_b1e(request_url, headers, "roaming_devices"):
        print("Failed to create the roaming devices")
        return False

    # Create Roaming Device Groups
    print("Creating the roaming device groups")
    if not create_dummy_b1Egroup(request_url, headers, "roaming_device_groups"):
        print("Failed to create the roaming device groups")
        return False

    # Create Onprem hosts
    print("Creating the onprem hosts")
    if not create_on_prem_hosts(request_url, headers, "on_prem_hosts"):
        print("Failed to create the onprem hosts")
        return False

    # Create Anycast
    print("Creating Anycast")
    if not create_anycast(request_url, headers, "ac_configs"):
        print("Failed to create Anycast")
        return False

    # Create Source Flow (NIOS)
    print("Creating the source flow (NIOS)")
    if not create_sources_flow(request_url, headers, "sources/nios"):
        print("Failed to create NIOS Source Flow")
        return False

    # Create Destination Flow (Reporting)
    print("Creating the Destination Flow")
    if not create_destinations_flow(request_url, headers, "destinations/reporting"):
        print("Failed to create the destination flow")
        return False

    # Create ETL/Filters
    print("Creating the ETL Filters")
    if not create_etl_filters_flow(request_url, headers, "etls/filters/ip_network"):
        print("Failed to create the ETL Filters")
        return False

    # Create Traffic Flow
    print("Creating the Traffic Flow")
    if not create_traffic_flow(request_url, headers, "flows/data"):
        print("Failed to create the Traffic Flow")
        return False

    print("Created the objects successfully!!")
    return True


# Create domains
def create_domains(count):
    list_of_domains = []
    for _ in range(1, count + 1):
        domain = 'www.' + ''.join(
            random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10)) + '.com'
        list_of_domains.append(domain)

    if len(list_of_domains) == 0:
        list_of_domains.append("error")
    return list_of_domains


# Create IP addresses
def create_ip(count):
    list_of_ip = []
    for _ in range(1, count + 1):
        ip = ".".join(map(str, (random.randint(0, 255)
                                for _ in range(4))))
        list_of_ip.append(ip)

    if len(list_of_ip) == 0:
        list_of_ip.append("100.100.100.100")
    return list_of_ip


# Create Random Mac addresses
def create_mac_addr(count):
    list_of_mac = []
    for _ in range(1, count + 1):
        mac_addr = "%02x:%02x:%02x:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255),
                                                      random.randint(0, 255), random.randint(0, 255),
                                                      random.randint(0, 255), random.randint(0, 255))
        list_of_mac.append(mac_addr)

    return list_of_mac


def create_policy_data(request_url, headers, feature=""):
    cl_info_lists = [{}]

    try:
        get_response = requests.get(request_url + "/api/atcfw/v1/" + "named_lists", headers=headers,
                                    timeout=TIMEOUT)
        if not get_response.ok:
            return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during GET operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("results"):
        if len(response["results"]) == 0:
            return True

    for items in response["results"]:
        if items["type"] == "custom_list":
            cl_info_lists.append({"data": str(items["name"]), "description": str(items["description"])})

    cl_info_lists.remove({})

    # Create policy rules
    try:
        rules = [{}]
        for d in cl_info_lists:
            rules.append(
                {"action": "action_log", "type": "custom_list", "data": d["data"], "description": d["description"]})

        rules.remove({})

        for i in range(1, 4):
            data["name"] = "sec_pol_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["description"] = "Auto-generated Test description" + str(i)
            data["ecs"] = False
            data["default_redirect_name"] = ""
            data["default_action"] = "action_allow"
            data["access_codes"] = []
            data["rules"] = [{}]
            for each_rules in rules:
                data["rules"].append(each_rules)
            data["rules"] = data["rules"].append(reset.get_default_security_policy_rules())

            post_response = requests.post(request_url + "/api/atcfw/v1/" + feature, headers=headers, timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                print("Error Response: ", post_response.content)
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False

    return True


def create_category_filter(request_url, headers, feature=""):
    categories = ["Alcohol", "Anonymizers"]
    try:
        for i in range(1, 4):
            data["name"] = "content_filter_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["description"] = "Auto-generated Test description" + str(i)
            data["categories"] = [categories[i % 2]]

            post_response = requests.post(request_url + "/api/atcfw/v1/" + feature, headers=headers, timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False

    return True


def create_custom_lists(request_url, headers, feature=""):
    domains = create_domains(3)
    ips = create_ip(3)
    items = domains + ips

    try:
        for i in range(1, 4):
            data["name"] = "custom_list_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["description"] = "Auto-generated Test description" + str(i)
            data["items"] = items
            data["type"] = "custom_list"
            post_response = requests.post(request_url + "/api/atcfw/v1/" + feature, headers=headers, timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                print("Error Response: ", post_response.content)
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False
    return True


def create_bypass_codes(request_url, headers, feature=""):
    try:
        for i in range(1, 4):
            data["name"] = "bypass_code_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["description"] = "Auto-generated Test description" + str(i)
            data["activation"] = "2100-01-01T00:00:00+00:00"
            data["expiration"] = "9999-12-31T23:59:59+00:00"
            data["rules"] = [{"data": "Threat Insight - Fast Flux", "type": "custom_list"},
                             {"data": "ransomware", "type": "named_feed"},
                             {"data": "malware-dga", "type": "named_feed"}]

            post_response = requests.post(request_url + "/api/atcfw/v1/" + feature, headers=headers, timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                print("Error Response: ", post_response.content)
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False

    return True


def create_internal_domains(request_url, headers, feature=""):
    domains = create_domains(3)
    ips = create_ip(3)
    items = domains + ips

    try:
        for i in range(1, 4):
            data["name"] = "internal_doms_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["description"] = "Auto-generated Test description" + str(i)
            data["internal_domains"] = items

            post_response = requests.post(request_url + "/api/atcfw/v1/" + feature, headers=headers, timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False
    return True


def create_network_lists(request_url, headers, feature=""):
    ips = create_ip(3)
    ip_networks = []
    for each_ip in ips:
        ip_networks.append(each_ip + "/32")

    try:
        for i in range(1, 4):
            data["name"] = "network_list_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["description"] = "Auto-generated Test description" + str(i)
            data["items"] = ip_networks

            post_response = requests.post(request_url + "/api/atcfw/v1/" + feature, headers=headers, timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                print("Error Response: ", post_response.content)
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False
    return True


def create_redirect_page(request_url, headers, feature=""):
    redirect_types = ["default", "custom"]

    try:
        for each_type in redirect_types:
            data["content"] = "<h1> Hello World, this is " + each_type + "</h1>"
            data["type"] = each_type

            put_response = requests.put(request_url + "/api/atcfw/v1/" + feature, headers=headers, timeout=TIMEOUT,
                                        data=json.dumps(data))
            if not put_response.ok:
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False
    return True


def create_dummy_b1e(request_url, headers, feature=""):
    try:
        for i in range(1, 3):
            data = {}
            data["user_id"] = "b1E_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["device_info"] = ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10))
            data["os_platform"] = "Windows " + str(i + 6)
            data["version"] = "1.8.2"
            data["client_id"] = ""
            fqdn = ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["net_info"] = {
                                "fqdn": fqdn, "ipv4_addr_list": create_ip(2),
                                "mac_addr": create_mac_addr(2),
                                "state": {"protection": "PENDING_ACCOUNT_CHECK", "upgrade": "NO_OPERATION"}
                                }

            post_response = requests.post(request_url + "/api/v1/cfwc/login", headers=headers, timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                print("Error Response: ", post_response.content)
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False
    return True


def create_dummy_b1Egroup(request_url, headers, feature=""):
    client_ids = []
    internal_domain_ids = []

    # Get roaming devices
    try:
        get_response = requests.get(request_url + "/api/atcep/v1/" + "roaming_devices", headers=headers,
                                    timeout=TIMEOUT)
        if not get_response.ok:
            return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during GET operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("results"):
        if len(response["results"]) == 0:
            return True

    for items in response["results"]:
        if len(items["client_id"]) is not 0:
            client_ids.append(items["client_id"])

    # Get internal domain lists
    try:
        get_response = requests.get(request_url + "/api/atcfw/v1/" + "internal_domain_lists", headers=headers,
                                    timeout=TIMEOUT)
        if not get_response.ok:
            return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during GET operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("results"):
        if len(response["results"]) == 0:
            return True

    for items in response["results"]:
        if items["is_default"] is not True:
            internal_domain_ids.append(items["id"])

    try:
        for i in range(1, 3):
            data["name"] = "b1E_group_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["description"] = ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10))
            data["is_default"] = False
            data["roaming_devices"] = [client_ids[i % 2]]
            data["internal_domain_lists"] = [internal_domain_ids[i % 2]]

            post_response = requests.post(request_url + "/api/atcep/v1/" + feature, headers=headers, timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False
    return True


def create_on_prem_hosts(request_url, headers, feature=""):
    try:
        for i in range(1, 3):
            data["display_name"] = "onprem_host_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["description"] = ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10))
            data["applications"] = [
                {"disabled": "0", "application_type": "9", "state": {"state_space": "28", "desired_state": "1"}}]

            post_response = requests.post(request_url + "/api/host_app/v1/" + feature, headers=headers, timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                print("Error Response: ", post_response.content )
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False
    return True


def create_anycast(request_url, headers, feature=""):
    anycast_ips = create_ip(4)
    onprem_hosts = [{}]
    services = ["DNS", "DFP"]

    try:
        get_response = requests.get(request_url + "/api/host_app/v1/" + "on_prem_hosts", headers=headers,
                                    timeout=TIMEOUT)
        if not get_response.ok:
            print("Error Response: ", get_response.content)
            return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False

    response_text = json.loads(get_response.text)
    if response_text.get("result"):
        if len(response_text["result"]) == 0:
            return True

    for items in response_text["result"]:
        onprem_hosts.append({"id": int(items["id"]), "name": items["display_name"]})
    onprem_hosts.remove({})

    count = 0
    try:
        for i in range(1, 3):
            count = count + 1
            data["anycast_ip_address"] = anycast_ips[i]
            data["name"] = "anycast_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["description"] = ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10))

            data["service"] = services[i % 2]

            if count > len(onprem_hosts):
                continue
            else:
                data["onprem_hosts"] = [onprem_hosts[i % 2]]

            post_response = requests.post(request_url + "/api/anycast/v1/accm/" + feature, headers=headers,
                                          timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                print("Error Response: ", post_response.content)
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False
    return True


# TODO: Create Notifications using API
# TODO: Currently getting Not allowed error


def create_sources_flow(request_url, headers, feature=""):
    # feature: sources/nios

    ip = create_ip(3)
    data = {}

    try:
        for i in range(1, 3):
            data["name"] = "sources_nios_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["description"] = " Test description Source flow NIOS " + str(i)
            data["address"] = ip[i]
            data["enabled"] = False
            data["insecure_mode"] = True
            data["nios_username"] = "kvp@infoblox.com"
            data["nios_password"] = "kvpInfoblox-1*"

            post_response = requests.post(request_url + "/api/cdc-flow/v1/" + feature, headers=headers,
                                          timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                print("Error response:", post_response.content)
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False
    return True


def create_destinations_flow(request_url, headers, feature=""):
    # feature: destinations/reporting
    ip = create_ip(2)
    data = {}

    try:
        for i in range(1, 3):
            data["name"] = "dest_nios_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["description"] = " Test description Destination flow NIOS " + str(i)
            data["address"] = ip[0]
            data["enabled"] = False
            data["username"] = "kvp@infoblox.com"
            data["password"] = "kvpInfoblox-1*"
            data["reporting_appliance_address"] = ip[1]

            post_response = requests.post(request_url + "/api/cdc-flow/v1/" + feature, headers=headers,
                                          timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                print("Error Response:", post_response.content)
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False
    return True


def create_etl_filters_flow(request_url, headers, feature=""):
    # feature: etls/filters/ip_network

    data = {}
    ip = create_ip(4)
    ip_network = []
    for each_ip in ip:
        ip_network.append(each_ip + "/32")

    try:
        for i in range(1, 3):
            data["name"] = "etl_filter_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["description"] = " Test description ETL/FILTER flow NIOS " + str(i)
            data["enabled"] = False
            data["data"] = ip_network

            post_response = requests.post(request_url + "/api/cdc-flow/v1/" + feature, headers=headers,
                                          timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                print("Error Response:", post_response.content)
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False
    return True


def create_traffic_flow(request_url, headers, feature=""):
    # feature: flows/data

    data = {}
    source_flag = True
    destination_flag = True
    etl_filter_flag = True
    source_ids = []
    destination_ids = []
    etl_filters_ids = []
    onprem_hosts = []

    # Get onprem hosts
    try:
        get_response = requests.get(request_url + "/api/host_app/v1/" + "on_prem_hosts", headers=headers,
                                    timeout=TIMEOUT)
        if not get_response.ok:
            print("Error response while retrieving Onprem hosts for Traffic Flow::", get_response.content)
            return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("results"):
        if len(response["results"]) == 0:
            return True

    for items in response["result"]:
        # onprem_hosts.append({"id": int(items["id"]), "name": str(items["display_name"])})
        onprem_hosts.append(int(items["id"]))

    # Get Sources
    try:
        get_response = requests.get(request_url + "/api/cdc-flow/v1/display/sources", headers=headers,
                                    timeout=TIMEOUT)
        if not get_response.ok:
            print("Error response while retrieving Sources for Traffic Flow::", get_response.content)
            return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("results"):
        if len(response["results"]) == 0:
            return True

    for items in response["results"]:
        if items["type"] == "SOURCE_NIOS":
            source_ids.append(items["id"])

    if len(source_ids) is 0:
        print("Warning: No source flows found!!")
        source_flag = False

    # Get Destinations
    try:
        get_response = requests.get(request_url + "/api/cdc-flow/v1/display/destinations", headers=headers,
                                    timeout=TIMEOUT)
        if not get_response.ok:
            print("Error response while retrieving Destinations for Traffic Flow::", get_response.content)
            return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("results"):
        if len(response["results"]) == 0:
            return True

    for items in response["results"]:
        if items["type"] == "DESTINATION_REPORTING":
            destination_ids.append(items["id"])

    if len(destination_ids) is 0:
        print("Warning: No source flows found!!")
        destination_flag = False

    # Get Destinations
    try:
        get_response = requests.get(request_url + "/api/cdc-flow/v1/display/etls/filters", headers=headers,
                                    timeout=TIMEOUT)
        if not get_response.ok:
            print("Error response while retrieving ETL filters for Traffic Flow::", get_response.content)
            return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("results"):
        if len(response["results"]) == 0:
            return True

    for items in response["results"]:
        if items["type"] == "FILTER_IP_NETWORK":
            etl_filters_ids.append(items["id"])

    if len(etl_filters_ids) is 0:
        print("Warning: No source flows found!!")
        etl_filter_flag = False

    if not (source_flag and destination_flag and etl_filter_flag):
        print("Cannot create Traffic flow")
        return False

    # Create Flows
    try:
        if len(source_ids) > len(destination_ids):
            total = len(destination_ids)
        else:
            total = len(source_ids)

        for i in range(1, total+1):
            if len(onprem_hosts) is 0:
                break

            data["name"] = "traffic_flow_" + ''.join(
                random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(5))
            data["description"] = " Test description ETL/FILTER flow NIOS " + str(i)
            data["enabled"] = False
            data["source"] = source_ids.pop()
            data["destination"] = destination_ids.pop()
            data["etl_filters"] = [etl_filters_ids[i % 2]]
            data["source_data_types"] = ["QUERY_RESP_LOG"]
            data["cdc_hosts"] = [onprem_hosts.pop()]

            post_response = requests.post(request_url + "/api/cdc-flow/v1/" + feature, headers=headers,
                                          timeout=TIMEOUT,
                                          data=json.dumps(data))
            if not post_response.ok:
                print("Error response ::", post_response.content)
                return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during POST operation", e, feature)
        return False
    return True


# Associate Internal domains with other objects
def associate_internal_domains(request_url, headers, feature=""):
    internal_domain_ids = []
    roaming_groups_ids = []

    if not create_internal_domains(request_url, headers, "internal_domain_lists"):
        print("Failed to create Internal domain lists")
        return False

    # Get internal domain lists
    try:
        get_response = requests.get(request_url + "/api/atcfw/v1/" + "internal_domain_lists", headers=headers,
                                    timeout=TIMEOUT)
        if not get_response.ok:
            return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during GET operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("results"):
        if len(response["results"]) == 0:
            return True

    for items in response["results"]:
        if items["is_default"] is not True:
            internal_domain_ids.append(items["id"])
    
    if len(internal_domain_ids) == 0:
        print("Empty List of internal domains")
        return False
        
    # Associate with Roaming Groups
    try:
        get_response = requests.get(request_url+"/api/atcep/v1/roaming_device_groups", headers=headers, timeout=TIMEOUT)
        if not get_response.ok:
            return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during GET operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return True
    response = json.loads(get_response.text)

    for items in response["results"]:
        if feature == "roaming_device_groups":
            if not items["is_default"]:
                roaming_groups_ids.append(items["id"])

    if len(roaming_groups_ids) == 0:
        print("No roaming groups were found")

    try:
        for i in range(len(roaming_groups_ids)):
            put_data = {"internal_domain_lists": [internal_domain_ids[i]], "name": "test" + str(i)}
            put_response = requests.put(request_url + "/api/atcep/v1/roaming_device_groups/"+str(roaming_groups_ids[i]), headers=headers,
                                        timeout=TIMEOUT, data=json.dumps(put_data))
            if not put_response.ok:
                print("Error Response: ", put_response.content)
                return False

    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during GET operation", e, feature)
        return False


# Associate Internal domains with other objects
def associate_networks(request_url, headers, feature=""):
    network_ids = []
    security_policies_ids = []
    rules = []

    # Get internal domain lists
    try:
        get_response = requests.get(request_url + "/api/atcfw/v1/" + "network_lists", headers=headers,
                                    timeout=TIMEOUT)
        if not get_response.ok:
            return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during GET operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("results"):
        if len(response["results"]) == 0:
            return True

    for items in response["results"]:
        if items["is_default"] is not True:
            network_ids.append(items["id"])

    if len(network_ids) == 0:
        print("Empty List of internal domains")
        return False

    # Associate with Security Policy
    try:
        get_response = requests.get(request_url + "/api/atcfw/v1/security_policies", headers=headers,
                                    timeout=TIMEOUT)
        if not get_response.ok:
            return False
    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during GET operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("results"):
        if len(response["results"]) == 0:
            return True
    response = json.loads(get_response.text)

    for items in response["results"]:
        if feature == "security_policies":
            if not items["is_default"]:
                security_policies_ids.append(items["id"])
                rules.append(items["rules"])

    if len(security_policies_ids) == 0:
        print("No security policies were found")

    try:
        for i in range(len(security_policies_ids)):
            put_data = {"network_lists": network_ids, "name": "test" + str(i), "description": " Test description", "default_action": "action_allow", "rules": rules[i]}
            put_response = requests.put(
                request_url + "/api/atcfw/v1/security_policies/" + str(security_policies_ids[i]), headers=headers,
                timeout=TIMEOUT, data=json.dumps(put_data))
            if not put_response.ok:
                print("Error Response: ", put_response.content)
                return False

    except requests.exceptions.Timeout as e:
        print("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        return False
    except requests.exceptions as e:
        print("Unknown exception occurred during GET operation", e, feature)
        return False

if __name__ == "__main__":
    post_data()
