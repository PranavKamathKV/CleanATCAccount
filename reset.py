#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import requests
import logging
import argparse
import sys  # getopt

data = {}
TIMEOUT = 5

log_formatter = logging.Formatter("[%(asctime)s] [%(levelname)-5.5s]  %(message)s")
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

consoleHandler = logging.StreamHandler(sys.stdout)
consoleHandler.setFormatter(log_formatter)
root_logger.addHandler(consoleHandler)


def set_filehandler_log(filepath):
    logpath = "/tmp/reset"
    if filepath is not None:
        logpath = filepath

    file_handler = logging.FileHandler("{0}.log".format(logpath))
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)


def init():
    parser = argparse.ArgumentParser(description='Cleans the CSP account for the given Auth token on the given cluster URL')
    parser.add_argument('--logging', action='store', dest='filepath',
                        help='Provide the fully qualified path of the filename (including the filename)')

    parser.add_argument('--auth', action='store', dest='auth_token',
                        help='Authentication token for a given account')
    parser.add_argument('--cluster', action='store', dest='cluster_name',
                        help='Cluster name where the reset should be done. '
                             'Example:'
                                '\t test-csp.infoblox.com')
    results = parser.parse_args()
    if len(sys.argv) < 2:
        root_logger.info("Usage: python reset.py <auth token> <cluster url>")
        root_logger.info("Try python reset.py -h for more options")
        return None, None

    set_filehandler_log(results.filepath)

    if results.auth_token is not None and results.cluster_name is not None:
        return results.auth_token, results.cluster_name


# Cleans ATCFW API objects
def clean_atcfw_api(feature, request_url, headers):
    store_list = []
    try:
        get_response = requests.get(request_url+"/api/atcfw/v1/"+feature, headers=headers, timeout=TIMEOUT)
        if not get_response.ok:
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out : {}". format(e))
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error: {} ". format(e))
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred  for {} during GET operation : {}".format(e, feature))
        return False

    response = json.loads(get_response.text)
    if response.get("results"):
        if len(response["results"]) == 0:
            return True

    for items in response["results"]:
            if feature == "internal_domain_lists":
                if not items["is_default"]:
                    store_list.append(items["id"])

            elif feature == "named_lists":
                if items["type"] == "custom_list":
                    store_list.append(items["id"])

            elif feature == "access_codes":
                store_list.append(items["access_key"])

            elif feature == "category_filters":
                store_list.append(items["id"])

            elif feature == "custom_redirects":
                store_list.append(items["id"])

            elif feature == "network_lists":
                store_list.append(items["id"])

            elif feature == "security_policies":
                if "is_default" in items and items["is_default"] is False:
                    store_list.append(items["id"])

    if len(store_list) is 0:
        return True
    data["ids"] = store_list
    root_logger.info("Deleting the Ids %s for %s", data["ids"], feature)

    if feature != "redirect_page":
        try:
            response = requests.delete(request_url + "/api/atcfw/v1/"+feature,  data=json.dumps(data), headers=headers)
            if not response.ok:
                root_logger.error("Failed to delete %s ", feature)
                root_logger.error("RESPONSE:", response.content)
                return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error while deleting ", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown error occurred while deleting",e,feature)
            return False

        try:
            new_response = requests.get(request_url + "/api/atcfw/v1/" + feature, headers=headers, timeout=TIMEOUT)
            if not new_response.ok:
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during GET operation", e, feature)
            return False

        resp = json.loads(new_response.text)
        if resp.get("results"):
            if len(resp["results"]) == 0:
                return True

            if isinstance(resp,list) and "results" in resp:
                resp = resp["results"][0]
            if resp.get("results","is_default") or resp.get("results","type").lower() is "default":
                return True
            root_logger.error("Failed to delete %d items", len(resp["results"]))
            root_logger.info("Items are ", resp["results"])
    else:
        root_logger.info("Deleting the redirect pages")
        try:
            put_data = {'content': '', 'type': 'custom'}
            response = requests.put(request_url + "/api/atcfw/v1/" + feature, headers=headers, data=json.dumps(put_data))
            if not response.ok:
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during PUT operation", e, feature)
            return False

        try:
            new_response = requests.get(request_url + "/api/atcfw/v1/" + feature, headers=headers)
            if not new_response.ok:
                root_logger.error("Error while retrieving the information for %s", feature)
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during GET operation", e, feature)
            return False

        resp = json.loads(new_response.text)
        if resp.get("results"):
            if len(resp["results"]) == 0:
                return True
            if resp.get("results", "type") is "default":
                return True
            root_logger.error("Failed to delete the custom redirect page")
            return False
    return True


# Cleans BloxOne Endpoints objects
def clean_atcep_api(feature, request_url, headers):
    store_list = []
    try:
        get_response = requests.get(request_url+"/api/atcep/v1/"+feature, headers=headers, timeout=TIMEOUT)
        if not get_response.ok :
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return True
    response = json.loads(get_response.text)

    for items in response["results"]:
        if feature == "roaming_device_groups":
            if not items["is_default"]:
                store_list.append(items["id"])

        elif feature == "roaming_devices":
            if items["calculated_status"] is not "DELETED":
                store_list.append(items["client_id"])

    if len(store_list) is 0:
        return True
    
    data["ids"] = store_list
    root_logger.info("Deleting the Ids %s", data["ids"])

    if feature == "roaming_devices":
        put_data = {"client_ids": store_list, "administrative_status": "DISABLED"}
        try:
            response = requests.put(request_url + "/api/atcep/v1/"+feature, headers=headers, data=json.dumps(put_data))
            if not response.ok:
                root_logger.error("Failed to disable roaming device")
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during GET operation", e, feature)
            return False

        put_data["administrative_status"] = "DELETED"
        try:
            response = requests.put(request_url + "/api/atcep/v1/" + feature, headers=headers, data=json.dumps(put_data))
            if not response.ok:
                root_logger.error("Failed to delete roaming device")
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during PUT operation", e, feature)
            return False

    elif feature == "roaming_device_groups":
        try:
            response = requests.delete(request_url + "/api/atcep/v1/"+feature, headers=headers, data=json.dumps(data))
            if not response.ok:
                root_logger.error("Failed to delete the %s ", feature)
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during DELETE operation", e, feature)
            return False

    try:
        new_response = requests.get(request_url + "/api/atcep/v1/" + feature, headers=headers)
        if not new_response.ok:
            root_logger.error("Error while retrieving the information for %s", feature)
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e, feature)
        return False

    resp = json.loads(new_response.text)
    if resp.get("results"):
        if len(resp["results"]) != 0:
            item = resp["results"][0]
            if item.get("is_default"):
                return True

            if feature == "roaming_devices":
                fail_count = 0
                for item in resp["results"]:
                    if "DELETED" not in item["calculated_status"]:
                        fail_count = fail_count + 1
                if fail_count > 0:
                    root_logger.error("Failed to delete %d items", fail_count)
                    return False

    return True


# Cleans Onprem hosts objects
def clean_onprem_hosts(feature, request_url, headers):
    store_list = []
    try:
        get_response = requests.get(request_url+"/api/host_app/v1/"+feature, headers=headers)
        if not get_response.ok :
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("result") is None:
        return True

    for items in response.get("result"):
        if feature == "on_prem_hosts":
            store_list.append(items["id"])

    if len(store_list) is 0:
        return True

    root_logger.info("Deleting %d Onprem Hosts", len(store_list))
    for list_id in store_list:
        try:
            response = requests.delete(request_url + "/api/host_app/v1/"+feature+"/"+str(list_id), headers = headers)
            if not response.ok:
                root_logger.error("Failed to delete %s : %d", feature, list_id)
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during DELETE operation", e, feature)
            return False
    try:
        new_response = requests.get(request_url + "/api/host_app/v1/" + feature, headers=headers)
        if not new_response.ok:
            root_logger.error("Failed to retrieve %s results", feature)
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e, feature)
        return False

    resp = json.loads(new_response.text)
    if resp.get("results"):
        if len(resp["results"]) != 0:
            root_logger.error("Failed to delete %d items", len(resp["results"]))
            root_logger.error("Items are ", resp["results"])
            return False
    return True


# Cleans Anycast feature objects
def clean_anycast(feature, request_url, headers):
    store_list = []
    try:
        get_response = requests.get(request_url+"/api/anycast/v1/accm/"+feature, headers=headers)
        if not get_response.ok :
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if not response.get("results"):
        return True
    if len(response["results"]) == 0:
        return True

    for items in response["results"]:
        if feature == "ac_configs":
                store_list.append(items["id"])

    if len(store_list) is 0:
        return True
    root_logger.info("Deleting %d Anycast-Configs", len(store_list))
    for list_id in store_list:
        try:
            response = requests.delete(request_url + "/api/anycast/v1/accm/"+feature+"/"+str(list_id), headers=headers)
            if not response.ok:
                root_logger.error("Failed to delete Anycast Config %d", list_id)
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during DELETE operation", e, feature)
            return False

    try:
        new_response = requests.get(request_url + "/api/anycast/v1/accm/" + feature, headers=headers, timeout=TIMEOUT)
        if not new_response.ok:
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e, feature)
        return False
    resp = json.loads(new_response.text)
    if resp.get("results"):
        if len(resp["results"]) != 0:
            root_logger.error("Failed to delete %d items", len(resp["results"]))
            root_logger.INFO("Items are ", resp["results"])
            return False
    return True


# Cleans JOIN Tokens
def clean_join_tokens(request_url, headers):
        store_list = []
        try:
            get_response = requests.get(request_url + "/atlas-host-activation/v1/jointoken", headers=headers, timeout=TIMEOUT)
            if not get_response.ok:
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during GET operation", e)
            return False
        response = json.loads(get_response.text)

        if response.get("results") is None:
            return True

        for items in response["results"]:
            if "ACTIVE" in items["status"]:
                list_id = items["id"].split("/")
                store_list.append(list_id[2])

        if len(store_list) is 0:
            return True
        data["id"] = store_list
        root_logger.info("Deleting the Ids %s", data["id"])

        for list_id in store_list:
            try:
                response = requests.delete(request_url +"/atlas-host-activation/v1/jointoken/"+list_id, headers=headers)
                if not response.ok:
                    root_logger.error("Failed to delete the JoinToken %s", list_id)
                    return False
            except requests.exceptions.Timeout as e:
                root_logger.exception("Request timed out ", e)
                return False
            except requests.exceptions.RequestException as e:
                root_logger.exception("Request error:", e)
                return False
            except requests.exceptions as e:
                root_logger.exception("Unknown exception occurred during DELETE operation", e)
                return False
        try:
            new_response = requests.get(request_url + "/atlas-host-activation/v1/jointoken", headers=headers, timeout=TIMEOUT)
            if not new_response.ok:
                root_logger.error("Failed to retrieve items for JoinTokens")
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during GET operation", e)
            return False
        resp = json.loads(new_response.text)
        if resp.get("results"):
            if len(resp["results"]) != 0:
                root_logger.error("Failed to delete %d items", len(resp["results"]))
                root_logger.info("Items are ", resp["results"])
                return False

        return True


# Cleans CDC Flow
def clean_cdc_flow(feature, request_url, headers):
    store_list = []
    flag = True

    try:
        get_response = requests.get(request_url+"/api/cdc-flow/v1/display/"+feature, headers = headers, timeout=TIMEOUT)
        if not get_response.ok:
            flag = False
            return flag
    except requests.exceptions.Timeout as e:
        flag = False
        root_logger.exception("Request timed out ", e)
        return flag
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        flag = False
        return flag
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e, feature)
        flag = False
        return flag

    response = json.loads(get_response.text)
    if response.get("results"):
        if len(response["results"]) == 0:
            return True
    response = json.loads(get_response.text)

    for items in response["results"]:
        if feature == "sources":
            store_list.append(items["id"])
        if feature == "destinations":
            store_list.append(items["id"])
        if feature == "flows":
            store_list.append(items["id"])
        if feature == "etls/filters":
            store_list.append(items["id"])

    if len(store_list) is 0:
        return True
    root_logger.info("Deleting id %d for %s", len(store_list), feature)
    for list_id in store_list:
        try:
            response = requests.delete(request_url + "/api/cdc-flow/v1/display/"+feature + "/"+str(list_id), headers=headers)
            if not response.ok:
                root_logger.error("Failed to delete %s with %d", feature, list_id)

        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            flag = False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            flag = False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during DELETE operation", e, feature)
            flag = False

    try:
        new_response = requests.get(request_url + "/api/cdc-flow/v1/display/" + feature, headers=headers, timeout=TIMEOUT)
        if not new_response.ok:
            root_logger.error("Failed to retrieve items for %s", feature)
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e, feature)
        return False
    resp = json.loads(new_response.text)
    if resp.get("results"):
        if len(resp["results"]) != 0 and (feature == "etls/filters" or feature == "flows"):
            root_logger.error("Failed to delete %d items", len(resp["results"]))
            root_logger.info("Items are %t", resp["results"])
            flag = False

        elif len(resp["results"]) != 1 and (feature == "sources" or feature == "destinations"):
            root_logger.error("Failed to delete %d items", len(resp["results"]))
            root_logger.info("Items are %t", resp["results"])
            flag = False

    return flag


# Cleans Notifications
def clean_notifications(feature,request_url, headers):
    # feature = user_alerts, account_alerts
    store_list = []
    try:
        get_response = requests.get(request_url+"/atlas-notifications-mailbox/v1/"+feature, headers=headers, timeout=TIMEOUT)
        if not get_response.ok:
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e, feature)
        return False

    response = json.loads(get_response.text)
    if response.get("results" ) is None:
        return True
    response = json.loads(get_response.text)

    for items in response["results"]:
        if feature == "account_alerts":
            store_list.append(items["id"])

        elif feature == "user_alerts":
            store_list.append(items["id"])

    if len(store_list) is 0:
        return True
    data["ids"] = store_list
    root_logger.info("Deleting the Ids %s", data["ids"])

    try:
        response = requests.delete( request_url + "/atlas-notifications-mailbox/v1/"+feature, headers=headers, data=json.dumps(data))
        if not response.ok:
            root_logger.error("Failed to delete the %s ", feature)
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during DELETE operation", e, feature)
        return False
    try:
        new_response = requests.get(request_url + "/atlas-notifications-mailbox/v1/" + feature, headers=headers, timeout=TIMEOUT)
        if not new_response.ok:
            root_logger.error("Failed to retrieve the items for %s", feature)
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e, feature)
        return False

    resp = json.loads(new_response.text)
    if resp.get("results"):
        if len(resp["results"]) != 0:
            root_logger.error("Failed to delete %d items", len(resp["results"]))
            root_logger.info("Items are ", resp["results"])
            return False

    return True


# Cleans Atlas Tags
def clean_atlas_tags(request_url, headers):
    store_list = []
    try:
        get_response = requests.get(request_url+"/api/atlas-tagging/v2/tags", headers=headers, timeout=TIMEOUT)
        if not get_response.ok :
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e)
        return False

    response = json.loads(get_response.text)
    if response.get("results") is None:
        return True

    for items in response["results"]:
        if "revoked" not in items["status"]:
            list_id = items["id"].split("/")
            store_list.append(str(list_id[2]))

    if len(store_list) is 0:
        return True

    root_logger.info("Deleting %d ids for tags", len(store_list))

    for list_id in store_list:
        try:
            response = requests.delete(request_url + "/api/atlas-tagging/v2/tags/"+list_id, headers=headers)
            if not response.ok:
                root_logger.error("Failed to delete tag with id %s", list_id)
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during DELETE operation", e)
            return False

    return True


# Clean IPAM and DHCP items from CSP
def clean_ipam_dhcp(feature, request_url, headers):
    store_list = []
    try:
        get_response = requests.get(request_url+"/api/ddi/v1/"+feature, headers=headers, timeout=TIMEOUT)
        if not get_response.ok :
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e)
        return False
    response = json.loads(get_response.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return True
    response = json.loads(get_response.text)

    for items in response["results"]:
        if feature == "/dhcp/fixed_address":
            store_list.append(items["id"])
        elif feature == "/dhcp/global":
            store_list.append(items["id"])
        elif feature == "/dhcp/ha_group":
            store_list.append(items["id"])
        elif feature == "/dhcp/hardware_filter":
            store_list.append(items["id"])
        elif feature == "/dhcp/option_code":
            store_list.append(items["id"])
        elif feature == "/dhcp/option_filter":
            store_list.append(items["id"])
        elif feature == "/dhcp/option_group":
            store_list.append(items["id"])
        elif feature == "/dhcp/option_space":
            store_list.append(items["id"])
        elif feature == "/dhcp/server":
            store_list.append(items["id"])
        elif feature == "/ipam/address":
            store_list.append(items["id"])
        elif feature == "/ipam/address_block":
            store_list.append(items["id"])
        elif feature == "/ipam/host":
            store_list.append(items["id"])
        elif feature == "/ipam/ip_space":
            store_list.append(items["id"])
        elif feature == "/ipam/range":
            store_list.append(items["id"])
        elif feature == "/ipam/subnet":
            store_list.append(items["id"])

    if len(store_list) is 0:
        return True
    root_logger.info("Deleting id %d for %s", len(store_list), feature)
    for list_id in store_list:
        try:
            response = requests.delete(request_url + "/api/ddi/v1/"+feature+"/"+str(list_id), headers = headers)
            if not response.ok:
                root_logger.error("Failed to delete %s with %d", feature, list_id)
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during DELETE operation", e, feature)
            return False
    try:
        new_response = requests.get(request_url + "/api/ddi/v1/" + feature, headers=headers, timeout=TIMEOUT)
        if not new_response.ok:
            root_logger.error("Failed to retrieve information for %s", feature)
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e, feature)
        return False
    resp = json.loads(new_response.text)
    if resp.get("results"):
        if len(resp["results"]) != 0:
            root_logger.error("Failed to delete %d items for %s", len(resp["results"]), feature)
            root_logger.error("Items are", resp["results"])
            return False

    return True


def reset_default_objects(feature, request_url, headers):
    root_logger.info("Getting the Default object for %s", feature)
    
    object_id = default_get_to_reset(feature, request_url, headers)
    if object_id is 0:
        root_logger.error("Failed to get the default object %s",feature)
        return False

    root_logger.info("Resetting the Default object for %s", feature)
    if not put_to_reset_defaults(feature, request_url, headers, object_id):
        root_logger.error("Failed to reset the Default Object %s", feature)
        return False
    return True


def default_get_to_reset(feature, request_url, headers):
    object_id = 0
    if feature == "roaming_device_groups":
        try:
            get_response = requests.get(request_url + "/api/atcep/v1/" + feature, headers=headers, timeout=TIMEOUT)
            if not get_response.ok:
                return 0
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return 0
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return 0
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during GET operation", e)
            return 0
    else:
        try:
            get_response = requests.get(request_url + "/api/atcfw/v1/" + feature, headers=headers, timeout=TIMEOUT)
            if not get_response.ok:
                return 0
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return 0
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return 0
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during GET operation", e)
            return 0

    response = json.loads(get_response.text)

    if response.get("results"):
        if len(response["results"]) == 0:
            return 0

    for items in response["results"]:
        if items["is_default"]:
            object_id = items["id"]

    if object_id is 0:
        root_logger.error("Could not get ID for ", feature)
        return 0
    return object_id


def put_to_reset_defaults(feature, request_url, headers, object_id):
    data = {"description": "Auto-generated"}
    default_internal_domain = 0
    default_policy_id = 0
    default_endpoint_group_id = 0
    
    # Get the default internal domain List ID
    try:
        get_default_id = requests.get(request_url + "/api/atcfw/v1/internal_domain_lists", headers=headers, timeout=TIMEOUT)
        if not get_default_id.ok:
            root_logger.warn("Could not get the default ID of internal domain lists to reset the default Endpoint Group")
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e)
        return False

    get_response = json.loads(get_default_id.text)

    if get_response.get("results"):
        if len(get_response["results"]) == 0:
            root_logger.error("Could not get the default Internal Domain info")
            return False

    for items in get_response["results"]:
        if items["is_default"]:
            default_internal_domain = items["id"]
            
    # Get the Default Security Policy ID
    try:
        get_default_policy_id = requests.get(request_url + "/api/atcfw/v1/security_policies", headers=headers, timeout=TIMEOUT)
        if not get_default_policy_id.ok:
            root_logger.warn("Could not get the default ID of security policies to reset the default Endpoint Group")
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e)
        return False

    get_response = json.loads(get_default_policy_id.text)

    if get_response.get("results"):
        if len(get_response["results"]) == 0:
            root_logger.error("Could not get the default Security Policy info")
            return False

    ## Get the Default Endpoint Group ID
    try:
        get_default_endpoint_group_id = requests.get(request_url + "/api/atcep/v1/roaming_device_groups", headers=headers, timeout=TIMEOUT)
        if not get_default_endpoint_group_id.ok:
            root_logger.warn("Could not get the default ID of the default Endpoint Group")
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e)
        return False

    get_response = json.loads(get_default_endpoint_group_id.text)

    if get_response.get("results"):
        if len(get_response["results"]) == 0:
            root_logger.error("Could not get the default Endpoint Group info")
            return False

    for items in get_response["results"]:
        if items["is_default"]:
            default_endpoint_group_id = items["id"]

    if feature == "roaming_devices_groups":
        custom_url = request_url + "/api/atcep/v1/" + feature + "/" + str(object_id)

        data["is_probe_enabled"] = True
        data["probe_domain"] = "probe.infoblox.com"
        data["probe_response"] = "9OBGDKGX6V8ATHDKDIK29QGF5WD30YQD"
        data["name"] = "All BloxOne Endpoints (Default)"
        data["description"] = "Auto-generated"
        data["roaming_devices"] = []
        data["policy_name"] = "Default Global Policy"

        if default_internal_domain is not 0 and default_policy_id is not 0:
            data["internal_domain_lists"] = default_internal_domain
            data["policy_id"] = default_policy_id
        elif default_policy_id is 0:
            root_logger.error("Could not get the default Security Policy info")
            return False
        elif default_internal_domain is 0:
            root_logger.error("Could not get the default Internal Domain info")
            return False

        try:
            put_response = requests.put(custom_url, headers=headers, data=json.dumps(data))
            if not put_response.ok:
                root_logger.warn("Could not reset the Default Endpoint Group")
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during GET operation", e)
            return False

    elif feature == "internal_domain_lists":
        custom_url = request_url + "/api/atcfw/v1/" + feature + "/" + str(object_id)
        data["internal_domains"] = ["example"]
        data["name"] = "Default Bypass Domains/CIDRs"

        try:
            put_response = requests.put(custom_url, headers=headers, data=json.dumps(data))
            if not put_response.ok:
                root_logger.warn("Could not reset the Default Internal Domain List")
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during GET operation", e)
            return False

    elif feature == "security_policies":
        custom_url = request_url + "/api/atcfw/v1/" + feature + "/" + str(object_id)
        data["access_codes"] = []
        data["default_action"] = "action_allow"
        data["default_redirect_name"] = ""
        data["ecs"] = False
        data["name"] = "Default Global Policy"
        data["rules"] = get_default_security_policy_rules()

        try:
            put_response = requests.put(custom_url, headers=headers, data=json.dumps(data))
            if not put_response.ok:
                root_logger.warn("Could not reset the Default Security Policy")
                return False
        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during GET operation", e)
            return False
        
    return True


def get_default_security_policy_rules():
    data = {"rules": [
        {
            "action": "action_block",
            "data": "base",
            "description": "Suspicious/malicious as destinations: Enables protection against known hostnames such as APT, Bot, Compromised Host/Domains, Exploit Kits, Malicious Name Servers, and Sinkholes.",
            "type": "named_feed"
        },
        {
            "action": "action_block",
            "data": "ext-base-antimalware",
            "description": "Suspicious/malicious as destinations: An extension of the Base and AntiMalware feed that contains recently expired hostname indicators with an extended time-to-live (TTL) applied. The extended time-to-live (TTL) provides an extended reach of protection for the DNS FW, but may also increase the risk of false positives as some of these Base and Antimalware feed related domains and hosts may no longer be active.",
            "type": "named_feed"
        },
        {
            "action": "action_block",
            "data": "antimalware",
            "description": "Suspicious/malicious as destinations: Enables protection against known malicious hostname threats that can take action on or control of your systems, such as Malware Command \u0026 Control, Malware Download, and active Phishing sites.",
            "type": "named_feed"
        },
        {
            "action": "action_block",
            "data": "exploitkit-ip",
            "description": "Suspicious/malicious as destinations: Enables protection against distributable packs that contains malicious programs that are used to execute \"drive-by download\" attacks "
                           "in order to infect users with malware. These exploit kits target vulnerabilities in the "
                           "users' machines (usually due to unpatched versions of Java, Adobe Reader, Adobe Flash, "
                           "Internet Explorer, …) to "
                           "load malware onto the victim's computer.",
            "type": "named_feed"
        },
        {
            "action": "action_block",
            "data": "ext-exploitkit-ip",
            "description": "Suspicious/malicious as destinations:  An extension of the Exploit Kits feed that contains recently expired ExploitKits with an extended time-to-live (TTL) applied. The extended time-to-live (TTL) provides an extended reach of protection the DNS FW, but may also increase the risk of false positives as some of these Exploit Kits IP's may no longer be active.",
            "type": "named_feed"
        },
        {
            "action": "action_block",
            "data": "ransomware",
            "description": "Suspicious/malicious as destinations: Enables protection against ransomware taking over your system. Ransomware will encrypt files on your system and require you to pay in order to get them decrypted. This feed prevents ransomware to contact the servers which it needs to encrypt your files.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "ext-ransomware",
            "description": "Suspicious/malicious as destinations: An extension of the Ransomware feed that contains recently expired Ransomware with an extended time-to-live (TTL) applied. The extended time-to-live (TTL) provides an extended reach of protection for the DNS FW, but may also increase the risk of false positives as some of the Ransomware related domains and hosts may no longer be active.",
            "type": "named_feed"
        },
        {
            "action": "action_block",
            "data": "malware-dga",
            "description": "Suspicious/malicious as destinations: Domain generation algorithm (DGA) are algorithms seen in various families of malware that are used to periodically generate a large number of domain names that can be used as rendezvous points with their command and control servers. Examples include Ramnit, Conficker, and Banjori.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "surbl-lite",
            "description": "Suspicious/malicious as destinations: Designed to fit on appliances with limitations on the number of threat intelligence entries that can be loaded, SURBL Multi lite is a subset of threat intelligence entries from the SURBL Multi threat feed. SURBL Multi Lite is narrowed down to include concise and targeted threat intelligence focusing on only the most current and fully malicious sites. The combined set includes malware, phishing and botnet activity.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "multi-domain.surbl",
            "description": "Suspicious/malicious as destinations: Blacklist of Malicious Domains including up-to-date intel on active malware, phishing, botnet, and spam domains. Based on data provided by our partner SURBL.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "antimalware-ip",
            "description": "Suspicious/malicious as destinations: Enables protection against known malicious or compromised IP addresses. These are known to host threats that can take action on or control of your systems, such as Malware Command \u0026 Control, Malware Download, and active Phishing sites.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "ext-antimalware-ip",
            "description": "Suspicious/malicious as destinations: An extension of the AntiMalware IP feed that contains recently expired Malware IP's with an extended time-to-live (TTL) applied. The extended time-to-live (TTL) provides an extended reach of protection for the DNS FW, but may also increase the risk of false positives as some of these Malware IP's may no longer be active.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "Threat Insight - Data Exfiltration",
            "description": "Auto-generated",
            "type": "custom_list"
        },
        {
            "action": "action_log",
            "data": "Threat Insight - DNS Messenger",
            "description": "Auto-generated",
            "type": "custom_list"
        },
        {
            "action": "action_log",
            "data": "Threat Insight - Fast Flux",
            "description": "Auto-generated",
            "type": "custom_list"
        },
        {
            "action": "action_log",
            "data": "Threat Insight - DGA",
            "description": "Auto-generated",
            "type": "custom_list"
        },
        {
            "action": "action_log",
            "data": "dhs-ais-domain",
            "description": "Suspicious/malicious as destinations: The Department of Homeland Security's (DHS) Automated Indicator Sharing (AIS) program enables the exchange of cyber threat indicators between the Federal Government and the private sector. AIS is a part of the Department of Homeland Security's effort to create an ecosystem where as soon as a company or federal agency observes an attempted compromise, the indicator is shared with AIS program partners, including Infoblox. Hostname Indicators contained in this feed are not validated by DHS as the emphasis is on velocity and volume. Infoblox does not modify or verify the indicators. However, indicators from the AIS program are classified and normalized by Infoblox to ease consumption. Data included in this feed includes AIS data subject to the U.S. Department of Homeland Security Automated Indicator Sharing Terms of Use available at https://www.us-cert.gov/ais and must be handled in accordance with the Terms of Use. Prior to further distributing the AIS data, you may be required to sign and submit the Terms of Use. Please email ncciccustomerservice@hq.dhs.gov for additional information.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "bogon",
            "description": "May choose to block based on company policy. Bogons are commonly found as the source addresses of DDoS attacks. \"Bogon\" is an informal name for an IP packet on the public Internet that claims to be from an area of the IP address space reserved, but not yet allocated or delegated by the Internet Assigned Numbers Authority (IANA) or a delegated Regional Internet Registry (RIR). The areas of unallocated address space are called \"bogon space\". Many ISPs and end-user firewalls filter and block bogons, because they have no legitimate use, and usually are the result of accidental or malicious misconfiguration.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "bot-ip",
            "description": "Indicators that are malicious as sources. IP's associated with botnet activity. Enables protection against self-propagating malware designed to infect a host and connect back to a central server or servers that act as a command and control (C\u0026C) center for an entire network of compromised devices, or \"botnet\". With a botnet, attackers can launch broad-based, \"remote-control\", flood-type attacks against their target(s). Bots can also log keystrokes, gather passwords, capture and analyze packets, gather financial information, launch DoS attacks, relay spam, and open back doors on the infected host.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "dhs-ais-ip",
            "description": "Suspicious/malicious as destinations: The Department of Homeland Security's (DHS) Automated Indicator Sharing (AIS) program enables the exchange of cyber threat indicators between the Federal Government and the private sector. AIS is a part of the Department of Homeland Security's effort to create an ecosystem where as soon as a company or federal agency observes an attempted compromise, the indicator is shared with AIS program partners, including Infoblox. IP Indicators contained in this feed are not validated by DHS as the emphasis is on velocity and volume. Infoblox does not modify or verify the indicators. However, indicators from the AIS program are classified and normalized by Infoblox to ease consumption. Data included in this feed includes AIS data subject to the U.S. Department of Homeland Security Automated Indicator Sharing Terms of Use available at https://www.us-cert.gov/ais and must be handled in accordance with the Terms of Use. Prior to further distributing the AIS data, you may be required to sign and submit the Terms of Use. Please email ncciccustomerservice@hq.dhs.gov for additional information.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "tor-exit-node-ip",
            "description": "Not necessarily malicious, but may be blocked based on company policy. Tor Exit Nodes are the gateways where encrypted Tor traffic hits the Internet. This means an exit node can be used to monitor Tor traffic (after it leaves the onion network). It is in the design of the Tor network that locating the source of that traffic through the network should be difficult to determine.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "ext-tor-exit-node-ip",
            "description": "Suspicious/malicious as destinations. An extension of the Tor Exit Nodes feed that contains recently expired Tor Exit Nodes with an extended time-to-live (TTL) applied. The extended time-to-live (TTL) provides an extended reach of protection for the DNS FW, but may also increase the risk of false positives as some of these Tor Exit Node IP's may no longer be active.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "eecn-ip",
            "description": "May choose to block based on company policy. Contains IP's assigned to countries in Eastern Europe and China. These countries are often found in cyber-attacks seeking intellectual property or other sensitive or classified data and stealing credit card or financial information. Countries include Belarus, Bulgaria, Czech Republic, Estonia, Hungary, Latvia, Lithuania, Moldova, Poland, Romania, Russian Federation, Slovakia, Turkey, Ukraine, and China. This feed includes Geo IP data provided by MaxMind.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "sanctions-ip",
            "description": "May choose to block based on company policy. Contains IP's assigned to United States sanctioned countries listed by US Treasury Office of Foreign Assets Control (OFAC). The Treasury Department's Office of Foreign Asset Control (OFAC) administers and enforces economic sanctions imposed by the United States against foreign countries. More information can be found by visiting the \"Sanctions Programs and Country Information\" page found here: https://www.treasury.gov/resource-center/sanctions/Programs/Pages/Programs.aspx. This feed includes Geo IP data provided by MaxMind.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "spambot-ip",
            "description": "Suspicious/malicious as sources. IPs of known spam servers. Enables protection against a computer or bot node as part of a botnet seen sending spam. IP's listed are also frequently found with a poor/negative reputation on that IP address. Recommended to run in \"logging\" mode prior to blocking to see what would have been blocked.  Can also be used to help block incoming Spam or potentially malicious emails from known spam sources by feeding into your email platform or appliance.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "cryptocurrency",
            "description": "The use and mining of cryptocurrency is not inherently benign or malicious, or used exclusively by threat actors or general users. However, over the last several years, it has been increasingly used for illegal and/or fraudulent activities such as human trafficking, black market sales/purchases, and ransomware payments, and others. Cryptocurrency mining can impair system performance and risk end users and businesses to information theft, hijacking, and a plethora of other malware. This feed features threats that allow malicious actors to perform illegal and/or fraudulent activities, coinhives that allows site owners to embed cryptocurrency mining software into their webpages as a replacement to normal advertising, Cryptojacking  that allows site owners  to mine for cryptocurrency without the owner's consent, and cryptocurrency mining pools working together to mine cryptocurrency. This feed features indicators of activity which may indicate malicious or unauthorized use of resources including: coinhive which can be embed into a site owners web pages to lie cryptocurrency with the visitors permission as an alternative to web banner advertising; cryptojacking where malicious actors use in-browser mining without the victim's consent; and cryptocurrency mining pools working together to mine cryptocurrency.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "nccic-host",
            "description": "Indicators contained in this feed appear on the watchlist from the National Cybersecurity \u0026 Communications Integration Center (NCCIC) and are not verified or validated by DHS or Infoblox. DHS's National Cybersecurity and Communications Integration Center (NCCIC) is a 24x7 cyber situational awareness, incident response, and management center that serves as the hub of information sharing activities among public and private sector partners to build awareness of vulnerabilities, incidents, and mitigations. Data included in this feed are subject to the U.S. Department of Homeland Security Automated Indicator Sharing Terms of Use available at: https://www.us-cert.gov/ais and must be handled in accordance with the Terms of Use. Please email ncciccustomerservice@hq.dhs.gov for additional information. Hostname Indicators contained in this feed have not been verified or validated and may contain false positives.  While these indicators may be used to detect suspicious activity, Infoblox recommends caution due to the potential to cause a user or customer outage. Recommended running in 'logging' mode prior to blocking to see what would have been blocked.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "nccic-ip",
            "description": "Indicators contained in this feed appear on the watchlist from the National Cybersecurity \u0026 Communications Integration Center (NCCIC) and are not verified or validated by DHS or Infoblox. DHS's National Cybersecurity and Communications Integration Center (NCCIC) is a 24x7 cyber situational awareness, incident response, and management center that serves as the hub of information sharing activities among public and private sector partners to build awareness of vulnerabilities, incidents, and mitigations. Data included in this feed are subject to the U.S. Department of Homeland Security Automated Indicator Sharing Terms of Use available at: https://www.us-cert.gov/ais and must be handled in accordance with the Terms of Use. Please email ncciccustomerservice@hq.dhs.gov for additional information. Hostname Indicators contained in this feed have not been verified or validated and may contain false positives.  While these indicators may be used to detect suspicious activity, Infoblox recommends caution due to the potential to cause a user or customer outage. Recommended running in 'logging' mode prior to blocking to see what would have been blocked.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "spambot-dnsbl-ip",
            "description": "In DNSBL format, this feed contains IPs of known spam servers. Enables protection against a computer or bot node as part of a botnet seen sending spam. Can be used to help block incoming Spam or potentially malicious emails from known spam sources by feeding into your email platform or appliance.",
            "type": "named_feed"
        },
        {
            "action": "action_log",
            "data": "fresh-domain.surbl",
            "description": "Indicators that are not necessarily malicious, but may be blocked based on company policy. Newly Observed Domains. SURBL Fresh feed provides critical, accurate, information on the time new domains are placed into service. Security policy can be easily applied (block, quarantine, walled garden, etc.) to prevent resolution of new domains, based on the user's defined policies. Based on data provided by our partner SURBL.",
            "type": "named_feed"
        }
    ]}

    # Add more rules if enhanced

    return data["rules"]


# Clean Users, Groups and Access Policy
def clean_users_and_groups(feature, request_url, headers):
    store_list = []
    try:
        get_response = requests.get(request_url+feature, headers=headers, timeout=TIMEOUT)
        if not get_response.ok:
            return False
    except requests.exceptions.Timeout as e:
        root_logger.exception("Request timed out ", e)
        return False
    except requests.exceptions.RequestException as e:
        root_logger.exception("Request error:", e)
        return False
    except requests.exceptions as e:
        root_logger.exception("Unknown exception occurred during GET operation", e)
        return False
    response = json.loads(get_response.text)
    if response.get("results"):
        if len(response["results"]) == 0:
            return True
    response = json.loads(get_response.text)

    for items in response["results"]:
        if feature == "/v2/users":
            list_id = str(items["id"]).split("/")
            store_list.append(list_id[2])

        elif feature == "/v2/groups":
            list_id = str(items["id"]).split("/")
            store_list.append(list_id[2])

        elif feature == "/authz/v1/access_policies":
            store_list.append(str(items["id"]))

    if len(store_list) is 0:
        return True
    root_logger.info("Deleting id %d for %s", len(store_list), feature)
    for list_id in store_list:
        try:
            response = requests.delete(request_url + feature+"/"+str(list_id), headers=headers)
            if not response.ok:
                root_logger.error("Failed to delete %s with %s", feature, list_id)

        except requests.exceptions.Timeout as e:
            root_logger.exception("Request timed out ", e)
            return False
        except requests.exceptions.RequestException as e:
            root_logger.exception("Request error:", e)
            return False
        except requests.exceptions as e:
            root_logger.exception("Unknown exception occurred during DELETE operation", e, feature)
            return False

    return True


def main():
    auth, request_url = init()
    if auth is None and request_url is None:
        return

    request_url = "https://" + request_url

    if __name__ == "__main__":

        # Add relevant Auth Token here
        headers = {'Content-Type': 'application/json', 'Authorization': "Token " + auth}

        # Add more features if necessary
        default_objects = ["roaming_device_groups", "security_policies", "internal_domain_lists"]
        policy_features = ["security_policies", "access_codes", "named_lists", "category_filters"]
        atcfw_features = ["internal_domain_lists", "network_lists", "redirect_page"]
        atcep_features = ["roaming_device_groups", "roaming_devices"]
        onprem_features = ["on_prem_hosts", "update_configs"]
        anycast_features = ["ac_configs"]
        notification_features = ["user_alerts", "account_alerts"]
        cdc_flow_features = ["flows", "sources", "destinations", "etls/filters"]
        ipam_dhcp_features = ["/dhcp/fixed_address", "/dhcp/global", "/dhcp/ha_group", "/dhcp/hardware_filter", "/dhcp/option_code", "/dhcp/option_filter",
                                 "/dhcp/option_group", "/dhcp/option_space", "/dhcp/server", "/ipam/address", "/ipam/address_block", "/ipam/host", "/ipam/ip_space", "/ipam/range", "/ipam/subnet"]
        users_features = ["/v2/users", "/authz/v1/access_policies", "/v2/groups"]

        for item in default_objects:
            print("Resetting the %s " % item)
            if not reset_default_objects(item, request_url, headers):
                root_logger.warn("ATTEMPT TO RESET THE DEFAULT: %s FAILED", item)

        for item in policy_features:
            print("Deleting the %s" % item)
            if not clean_atcfw_api(item, request_url, headers):
                root_logger.warn("ATTEMPT TO DELETE THE FEATURE: %s FAILED", item)

        for item in atcep_features:
            print("Deleting the %s" % item)
            if not clean_atcep_api(item, request_url, headers):
                root_logger.warn('ATTEMPT TO DELETE THE FEATURE: %s FAILED', item)

        for item in onprem_features:
            print("Deleting the %s" % item)
            if not clean_onprem_hosts(item, request_url,headers):
                root_logger.warn("ATTEMPT TO DELETE THE FEATURE: %s FAILED", item)

        for item in atcfw_features:
            print("Deleting the %s" % item)
            if not clean_atcfw_api(item, request_url, headers):
                root_logger.warn("ATTEMPT TO DELETE THE FEATURE: %s FAILED", item)

        print("Revoking the join tokens from the CSP")
        if not clean_join_tokens(request_url, headers):
            root_logger.warn("ATTEMPT TO REVOKE THE JOIN TOKEN FAILED")

        for item in anycast_features:
            print("Deleting the %s" % item)
            if not clean_anycast(item, request_url, headers):
                root_logger.warn("ATTEMPT TO DELETE THE FEATURE: %s FAILED", item)

        for item in cdc_flow_features:
            print("Deleting the %s" % item)
            if not clean_cdc_flow(item, request_url, headers):
                root_logger.warn("ATTEMPT TO DELETE THE FEATURE: %s FAILED", item)

        for item in notification_features:
            print("Deleting the %s" % item)
            if not clean_notifications(item, request_url, headers):
                root_logger.warn("ATTEMPT TO DELETE THE FEATURE: %s FAILED", item)

        print("Revoking the Tags from the CSP")
        if not clean_atlas_tags(request_url, headers):
            root_logger.warn("ATTEMPT TO REVOKE TAGGING FAILED")

        # for item in ipam_dhcp_features:
        #     print("Deleting the %s" % item)
        #     if not clean_ipam_dhcp(item, request_url, headers):
        #         root_logger.warn("ATTEMPT TO DELETE THE FEATURE: %s FAILED", item)

        for item in default_objects:
            print("Resetting the %s " % item)
            if not reset_default_objects(item, request_url, headers):
                root_logger.warn("ATTEMPT TO RESET THE DEFAULT: %s FAILED", item)

        for item in users_features:
            print("Deleting the %s" % item)
            if not clean_users_and_groups(item, request_url, headers):
                root_logger.warn("ATTEMPT TO DELETE THE FEATURE: %s FAILED", item)


main()
