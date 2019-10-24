import random
import string
import json
import requests
import logging
import sys  ##, getopt

data =  {}
logging.basicConfig(level=logging.INFO)
TIMEOUT = 5
## Cleans ATCFW API objects
def cleanATCFWAPI(feature, requestURL, headers):
    storeList = []
    try:
        getResponse = requests.get(requestURL+"/api/atcfw/v1/"+feature, headers = headers, timeout = TIMEOUT)
        if not getResponse.ok:
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e, feature)
        return

    response = json.loads(getResponse.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return

    for items in response["results"]:
            if feature == "internal_domain_lists":
                if not items["is_default"]:
                    storeList.append(items["id"])

            elif feature == "named_lists":
                if items["type"] == "custom_list":
                    storeList.append(items["id"])

            elif feature == "access_codes":
                storeList.append(items["id"])

            elif feature == "category_filters":
                storeList.append(items["id"])

            elif feature == "custom_redirects":
                storeList.append(items["id"])

            elif feature == "network_lists":
                storeList.append(items["id"])

            elif feature == "security_policies":
                if "is_default" in items and items["is_default"] == False:
                    storeList.append(items["id"])

    data["ids"] = storeList
    logging.info("Deleting the Ids %s", data["ids"])

    if feature != "redirect_page":
        try:
            response = requests.delete( requestURL + "/api/atcfw/v1/"+feature, headers=headers, data=json.dumps(data))
            if not response.ok:
                logging.error("Failed to delete %s ", feature)
        except requests.exceptions.RequestException as e:
            logging.exception("Request error while deleting ", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown error occured while deleting",e,feature)
            return

        try:
            newResponse = requests.get(requestURL + "/api/atcfw/v1/" + feature, headers=headers, timeout = TIMEOUT)
            if not newResponse.ok:
                return
        except requests.exceptions.Timeout as e:
            logging.exception("Request timed out ", e)
            return
        except requests.exceptions.RequestException as e:
            logging.exception("Request error:", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown exception occured during GET operation", e, feature)
            return

        resp = json.loads(newResponse.text)
        if resp.get("results"):
            if len(resp["results"]) == 0:
                return

            if isinstance(resp,list) and "results" in resp:
                resp = resp["results"][0]
            if resp.get("results","is_default") or resp.get("results","type").lower() is "default":
                return
            logging.error("Failed to delete %d items", len(resp["results"]))
            logging.INFO("Items are ", resp["results"])
    else:
        logging.info("Deleting the redirect pages")
        try:
            putData = {'content': '', 'type': 'custom'}
            response = requests.put(requestURL + "/api/atcfw/v1/" + feature, headers=headers, data=json.dumps(putData))
            if not response.ok:
                return
        except requests.exceptions.Timeout as e:
            logging.exception("Request timed out ", e)
            return
        except requests.exceptions.RequestException as e:
            logging.exception("Request error:", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown exception occured during PUT operation", e, feature)
            return

        try:
            newResponse = requests.get(requestURL + "/api/atcfw/v1/" + feature, headers=headers)
            if not newResponse.ok:
                logging.error("Error while retrieving the information for %s", feature)
                return
        except requests.exceptions.Timeout as e:
            logging.exception("Request timed out ", e)
            return
        except requests.exceptions.RequestException as e:
            logging.exception("Request error:", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown exception occured during GET operation", e, feature)
            return

        resp = json.loads(newResponse.text)
        if resp.get("results"):
            if len(resp["results"]) == 0:
                return
            if resp.get("results", "type") is "default":
                return
            logging.error("Failed to delete the custom redirect page")
            return

## Cleans BloxOne Endpoints objects
def cleanATCEPAPI(feature, requestURL, headers):
    storeList = []
    try:
        getResponse = requests.get(requestURL+"/api/atcep/v1/"+feature, headers = headers, timeout=TIMEOUT )
        if not getResponse.ok :
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e, feature)
        return

    response = json.loads(getResponse.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return
    response = json.loads(getResponse.text)

    for items in response["results"]:
        if feature == "roaming_device_groups":
            if items["is_default"] == "false":
                storeList.append(items["ids"])

        elif feature == "roaming_devices":
            storeList.append(items["client_id"])

    data["ids"] = storeList
    logging.info("Deleting the Ids %s", data["ids"])

    if feature == "roaming_devices":
        putData = {}
        putData["client_ids"] = storeList
        putData["administrative_status"] = "DISABLED"
        try:
            response = requests.put(requestURL + "/api/atcep/v1/"+feature, headers = headers, data = json.dumps(putData))
            if not response.ok:
                logging.error("Failed to disable roaming device")
                return
        except requests.exceptions.Timeout as e:
            logging.exception("Request timed out ", e)
            return
        except requests.exceptions.RequestException as e:
            logging.exception("Request error:", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown exception occured during GET operation", e, feature)
            return

        putData["administrative_status"] = "DELETED"
        try:
            response = requests.put(requestURL + "/api/atcep/v1/" + feature, headers=headers, data=json.dumps(putData))
            if not response.ok:
                logging.error("Failed to delete roaming device")
                return
        except requests.exceptions.Timeout as e:
            logging.exception("Request timed out ", e)
            return
        except requests.exceptions.RequestException as e:
            logging.exception("Request error:", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown exception occured during PUT operation", e, feature)
            return

    elif feature == "roaming_device_groupgs":
        try:
            response = requests.delete( requestURL + "/api/atcep/v1/"+feature, headers=headers, data=json.dumps(data))
            if not response.ok:
                logging.error("Failed to delete the %s ", feature)
        except requests.exceptions.Timeout as e:
            logging.exception("Request timed out ", e)
            return
        except requests.exceptions.RequestException as e:
            logging.exception("Request error:", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown exception occured during DELETE operation", e, feature)
            return

    try:
        newResponse = requests.get(requestURL + "/api/atcep/v1/" + feature, headers=headers)
        if not newResponse.ok:
            logging.error("Error while retrieving the information for %s", feature)
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e, feature)
        return

    resp = json.loads(newResponse.text)
    if resp.get("results"):
        if len(resp["results"]) != 0:
            item = resp["results"][0]
            if item.get("is_default"):
                return
            logging.INFO("Items are ", resp["results"])
            logging.error("Failed to delete  %d item",  len(resp["results"]))

## Cleans Onprem hosts objects
def cleanOnPremHosts(feature, requestURL, headers):
    storeList = []
    try:
        getResponse = requests.get(requestURL+"/api/host_app/v1/"+feature, headers = headers)
        if not getResponse.ok :
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e, feature)
        return

    response = json.loads(getResponse.text)
    if response.get("results")  ==  None :
        return

    for items in response.get("results"):
        if feature == "on_prem_hosts":
                storeList.append(items["id"])

    logging.info("Deleting %d Onprem Hosts", len(storeList))
    for id in storeList:
        try:
            response = requests.delete(requestURL + "/api/host_app/v1/"+feature/id, headers = headers)
            if not response.ok:
                logging.error("Failed to delete %s : %d", feature, id)
        except requests.exceptions.Timeout as e:
            logging.exception("Request timed out ", e)
            return
        except requests.exceptions.RequestException as e:
            logging.exception("Request error:", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown exception occured during DELETE operation", e, feature)
            return
    try:
        newResponse = requests.get(requestURL + "/api/host_app/v1/" + feature, headers=headers)
        if not newResponse.ok:
            logging.error("Failed to retrieve %s results", feature)
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e, feature)
        return

    resp = json.loads(newResponse.text)
    if resp.get("results"):
        if len(resp["results"]) != 0:
            logging.error("Failed to delete %d items", len(resp["results"]))
            logging.error("Items are ", resp["results"])

## Cleans Anycast feature objects
def cleanAnycast(feature, requestURL, headers):
    storeList = []
    try:
        getResponse = requests.get(requestURL+"/api/anycast/v1/accm"+feature, headers = headers)
        if not getResponse.ok :
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e, feature)
        return

    response = json.loads(getResponse.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return
    response = json.loads(getResponse.text)

    for items in response["results"]:
        if feature == "ac_configs":
                storeList.append(items["ids"])

    logging.info("Deleting %d Anycast-Configs", len(storeList))
    for id in storeList:
        try:
            response = requests.delete(requestURL + "/api/anycast/v1/accm"+feature/id, headers = headers)
            if not response.ok:
                logging.error("Failed to delete Anycast Config %d", id)
        except requests.exceptions.Timeout as e:
            logging.exception("Request timed out ", e)
            return
        except requests.exceptions.RequestException as e:
            logging.exception("Request error:", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown exception occured during DELETE operation", e, feature)
            return

    try:
        newResponse = requests.get(requestURL + "/api/anycast/v1/accm" + feature, headers=headers, timeout=TIMEOUT)
        if not newResponse.ok:
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e, feature)
        return
    resp = json.loads(newResponse.text)
    if resp.get("results"):
        if len(resp["results"]) != 0:
            logging.error("Failed to delete %d items", len(resp["results"]))
            logging.INFO("Items are ", resp["results"])
            return

# Cleans JOIN Tokens
def cleanJoinTokens(requestURL, headers):
        storeList = []
        try:
            getResponse = requests.get(requestURL + "/atlas-host-activation/v1/jointoken", headers=headers, timeout=TIMEOUT)
            if not getResponse.ok:
                return
        except requests.exceptions.Timeout as e:
            logging.exception("Request timed out ", e)
            return
        except requests.exceptions.RequestException as e:
            logging.exception("Request error:", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown exception occured during GET operation", e)
            return
        response = json.loads(getResponse.text)

        if response.get("results") == None:
            return

        for items in response["results"]:
            id = items["id"].split("/")
            storeList.append(id[2])

        data["id"] = storeList
        logging.info("Deleting the Ids %s", data["id"])

        for id in storeList:
            try:
                response = requests.delete(requestURL +"/atlas-host-activation/v1/jointoken/"+id, headers = headers)
                if not response.ok:
                    logging.error("Failed to delete the JoinToken %s", id)
            except requests.exceptions.Timeout as e:
                logging.exception("Request timed out ", e)
                return
            except requests.exceptions.RequestException as e:
                logging.exception("Request error:", e)
                return
            except requests.exceptions as e:
                logging.exception("Unknown exception occured during DELETE operation", e)
                return
        try:
            newResponse = requests.get(requestURL + "/atlas-host-activation/v1/jointoken", headers=headers, timeout=TIMEOUT)
            if not newResponse.ok:
                logging.error("Failed to retrieve items for JoinTokens")
                return
        except requests.exceptions.Timeout as e:
            logging.exception("Request timed out ", e)
            return
        except requests.exceptions.RequestException as e:
            logging.exception("Request error:", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown exception occured during GET operation", e)
            return
        resp = json.loads(newResponse.text)
        if resp.get("results"):
            if len(resp["results"]) != 0:
                logging.error("Failed to delete %d items", len(resp["results"]))
                logging.info("Items are ", resp["results"])
                return

# Cleans CDC Flow
def cleanCDCFlow(feature, requestURL, headers):
    storeList = []
    try:
        getResponse = requests.get(requestURL+"/api/cdc-flow/v1/display"+feature, headers = headers, timeout=TIMEOUT)
        if not getResponse.ok :
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e, feature)
        return

    response = json.loads(getResponse.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return
    response = json.loads(getResponse.text)

    for items in response["results"]:
        if feature == "sources":
            storeList.append(items["ids"])
        if feature == "destinations":
            storeList.append(items["ids"])
        if feature == "flows":
            storeList.append(items["ids"])
        if feature == "etl/filters":
            storeList.append(items["ids"])

    logging.info("Deleting id %d for %s", len(storeList), feature)
    for id in storeList:
        try:
            response = requests.delete(requestURL + "/api/cdc-flow/v1/display"+feature/id, headers = headers)
            if not response.ok:
                logging.error("Failed to delete %s with %d", feature, id)
        except requests.exceptions.Timeout as e:
            logging.exception("Request timed out ", e)
            return
        except requests.exceptions.RequestException as e:
            logging.exception("Request error:", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown exception occured during DELETE operation", e, feature)
            return
    try:
        newResponse = requests.get(requestURL + "/api/cdc-flow/v1/display" + feature, headers=headers, timeout=TIMEOUT)
        if not newResponse.ok:
            logging.error("Failed to retrieve items for %s", feature)
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e, feature)
        return
    resp = json.loads(newResponse.text)
    if resp.get("results"):
        if len(resp["results"]) != 0:
            logging.error("Failed to delete %d items", len(resp["results"]))
            logging.info("Items are ", resp["results"])
            return

## Cleans Notifications
def cleanNotifications(feature,requestURL, headers):
    ## feature = user_alerts, account_alerts
    storeList = []
    try:
        getResponse = requests.get(requestURL+"/atlas-notifications-mailbox/v1/"+feature, headers = headers, timeout=TIMEOUT)
        if not getResponse.ok :
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e, feature)
        return

    response = json.loads(getResponse.text)
    if response.get("results" ) is None:
        return
    response = json.loads(getResponse.text)

    for items in response["results"]:
        if feature == "account_alerts":
                storeList.append(items["id"])

        elif feature == "user_alerts":
            storeList.append(items["id"])

    data["ids"] = storeList
    logging.info("Deleting the Ids %s", data["ids"])

    try:
        response = requests.delete( requestURL + "/atlas-notifications-mailbox/v1/"+feature, headers=headers, data=json.dumps(data))
        if not response.ok:
            logging.error("Failed to delete the %s ", feature)
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during DELETE operation", e, feature)
        return
    try:
        newResponse = requests.get(requestURL + "/atlas-notifications-mailbox/v1/" + feature, headers=headers, timeout=TIMEOUT)
        if not newResponse.ok:
            logging.error("Failed to retrieve the items for %s", feature)
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e, feature)
        return

    resp = json.loads(newResponse.text)
    if resp.get("results"):
        if len(resp["results"]) != 0:
            logging.error("Failed to delete %d items", len(resp["results"]))
            logging.info("Items are ", resp["results"])
            return

# Cleans Atlas Tags
def cleanAtlasTags(requestURL, headers):
    storeList = []
    try:
        getResponse = requests.get(requestURL+"/api/atlas-tagging/v2/tags", headers = headers, timeout=TIMEOUT)
        if not getResponse.ok :
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e)
        return

    response = json.loads(getResponse.text)
    if response.get("results" ) is None:
        return

    for items in response["results"]:
        storeList.append(items["id"])
    data["ids"] = storeList
    logging.info("Deleting ids %d for tags", len(storeList))
    for id in storeList:
        try:
            response = requests.delete(requestURL + "/api/atlas-tagging/v2/tags", headers = headers, data=json.dumps(data))
            if not response.ok:
                logging.error("Failed to delete tag with %d",id)
        except requests.exceptions.Timeout as e:
            logging.exception("Request timed out ", e)
            return
        except requests.exceptions.RequestException as e:
            logging.exception("Request error:", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown exception occured during DELETE operation", e)
            return


# Clean IPAM and DHCP items from CSP
def cleanIPAMDHCP(feature, requestURL, headers):
    storeList = []
    try:
        getResponse = requests.get(requestURL+"/api/ddi/v1/"+feature, headers = headers,timeout=TIMEOUT)
        if not getResponse.ok :
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e)
        return
    response = json.loads(getResponse.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return
    response = json.loads(getResponse.text)

    for items in response["results"]:
        if feature == "/dhcp/fixed_address":
            storeList.append(items["id"])
        elif feature == "/dhcp/global":
            storeList.append(items["id"])
        elif feature == "/dhcp/ha_group":
            storeList.append(items["id"])
        elif feature == "/dhcp/hardware_filter":
            storeList.append(items["id"])
        elif feature == "/dhcp/option_code":
            storeList.append(items["id"])
        elif feature == "/dhcp/option_filter":
            storeList.append(items["id"])
        elif feature == "/dhcp/option_group":
            storeList.append(items["id"])
        elif feature == "/dhcp/option_space":
            storeList.append(items["id"])
        elif feature == "/dhcp/server":
            storeList.append(items["id"])
        elif feature == "/ipam/address":
            storeList.append(items["id"])
        elif feature == "/ipam/address_block":
            storeList.append(items["id"])
        elif feature == "/ipam/host":
            storeList.append(items["id"])
        elif feature == "/ipam/ip_space":
            storeList.append(items["id"])
        elif feature == "/ipam/range":
            storeList.append(items["id"])
        elif feature == "/ipam/subnet":
            storeList.append(items["id"])

    logging.info("Deleting id %d for %s", len(storeList), feature)
    for id in storeList:
        try:
            response = requests.delete(requestURL + "/api/ddi/v1/"+feature/id, headers = headers)
            if not response.ok:
                logging.error("Failed to delete %s with %d", feature, id)
        except requests.exceptions.Timeout as e:
            logging.exception("Request timed out ", e)
            return
        except requests.exceptions.RequestException as e:
            logging.exception("Request error:", e)
            return
        except requests.exceptions as e:
            logging.exception("Unknown exception occured during DELETE operation", e, feature)
            return
    try:
        newResponse = requests.get(requestURL + "/api/ddi/v1/" + feature, headers=headers, timeout=TIMEOUT)
        if not newResponse.ok:
            logging.error("Failed to retrieve information for %s", feature)
            return
    except requests.exceptions.Timeout as e:
        logging.exception("Request timed out ", e)
        return
    except requests.exceptions.RequestException as e:
        logging.exception("Request error:", e)
        return
    except requests.exceptions as e:
        logging.exception("Unknown exception occured during GET operation", e, feature)
        return
    resp = json.loads(newResponse.text)
    if resp.get("results"):
        if len(resp["results"]) != 0:
            logging.error("Failed to delete %d items for %s", len(resp["results"]), feature)
            logging.error("Items are", resp["results"])
            return

def main(argv):
    if __name__ == "__main__":
        ### Add relevant Auth Token here
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Token e75e4a08e2ae81230cc1f9b645b2e2a6',
        }
        requestURL = ""

        print("Usage:\n <program> <API TOKEN> <CLUSTER URL>")
        #logging.INFO("Usage: <program> <API TOKEN> <CLUSTER URL>")
        if len(argv) != 2:
            sys.exit("Not enough arguments in the command line")

        headers['Authorization'] = "Token " + argv[0]
        requestURL = argv[1]

        ## Add more features if necessary
        #####"redirect_page", TODO
        atcfwFeatures = ["security_policies",  "internal_domain_lists", "named_lists", "custom_redirects", "network_lists", "access_codes", "category_filters", "redirect_page"]
        atcepFeatures = ["roaming_device_groups", "roaming_devices"]
        onPremFeatures = ["on_prem_hosts", "update_configs"]
        anycastFeatures = ["ac_configs"]
        notificationFeatures = ["user_alerts", "account_alerts"]
        cdcFlowFeatures = ["sources","destinations", "flows", "etl/filters"]
        ipamDHCPFeatures = ["/dhcp/fixed_address", "/dhcp/global", "/dhcp/ha_group", "/dhcp/hardware_filter", "/dhcp/option_code", "/dhcp/option_filter",
                            "/dhcp/option_group", "/dhcp/option_space", "/dhcp/server", "/ipam/address", "/ipam/address_block", "/ipam/host", "/ipam/ip_space", "/ipam/range", "/ipam/subnet"]

        for item in atcepFeatures:
            cleanATCEPAPI(item, requestURL, headers)

        for item in onPremFeatures:
            cleanOnPremHosts(item, requestURL,headers)

        for item in atcfwFeatures:
            cleanATCFWAPI(item, requestURL, headers)

        cleanJoinTokens(requestURL, headers)

        for item in anycastFeatures:
            cleanAnycast(item, requestURL, headers)

        for item in cdcFlowFeatures:
            cleanCDCFlow(item, requestURL, headers)

        for item in notificationFeatures:
            cleanNotifications(item, requestURL, headers)

        cleanAtlasTags(requestURL, headers)

        for item in ipamDHCPFeatures:
            cleanIPAMDHCP(item, requestURL, headers)

main(sys.argv[1:])
