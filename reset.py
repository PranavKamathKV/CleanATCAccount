import random
import string
import json
import requests
import logging
import sys  ##, getopt

data =  {}
logging.basicConfig(level=logging.INFO)

## Cleans ATCFW API objects
def cleanATCFWAPI(feature, requestURL, headers):
    storeList = []
    getResponse = requests.get(requestURL+"/api/atcfw/v1/"+feature, headers = headers)
    if not getResponse.ok :
        return
    response = json.loads(getResponse.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return
    logging.info(getResponse.text)

    for items in response["results"]:
        if feature == "internal_domain_lists":
            if items["is_default"] == "false":
                storeList.append(items["ids"])

        elif feature == "named_lists":
            if items["type"] == "custom_list":
                storeList.append(items["id"])

        elif feature == "access_codes":
            storeList.append(items["ids"])

        elif feature == "category_filters":
            storeList.append(items["ids"])

        elif feature == "custom_redirects":
            storeList.append(items["ids"])

        elif feature == "network_lists":
            storeList.append(items["ids"])

        elif feature == "security_policies":
            if items["is_default"] == "false":
                storeList.append(items["ids"])

    data["ids"] = storeList
    logging.info("Deleting the Ids %s", data["ids"])

    response = requests.delete( requestURL + "/api/atcfw/v1/"+feature, headers=headers, data=json.dumps(data))
    if not response.ok:
        logging.error("Failed to delete %s ", feature)

## Cleans BloxOne Endpoints objects
def cleanATCEPAPI(feature, requestURL, headers):
    storeList = []
    getResponse = requests.get(requestURL+"/api/atcep/v1/"+feature, headers = headers)
    if not getResponse.ok :
        return
    response = json.loads(getResponse.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return
    response = json.loads(getResponse.text)
    logging.info(getResponse.text)

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
        response = requests.put(requestURL + "/api/atcep/v1/"+feature, headers = headers, data = json.dumps(putData))
        if not response.ok:
            logging.error("Failed to disable roaming device")
            return

        putData["administrative_status"] = "DELETED"

        response = requests.put(requestURL + "/api/atcep/v1/" + feature, headers=headers, data=json.dumps(putData))
        if not response.ok:
            logging.error("Failed to delete roaming device")
            return

    elif feature == "roaming_device_groupgs":
        response = requests.delete( requestURL + "/api/atcep/v1/"+feature, headers=headers, data=json.dumps(data))
        if not response.ok:
            logging.error("Failed to delete the %s ", feature)

## Cleans Onprem hosts objects
def cleanOnPremHosts(feature, requestURL, headers):
    storeList = []
    getResponse = requests.get(requestURL+"/api/host_app/v1/"+feature, headers = headers)
    if not getResponse.ok :
        return
    response = json.loads(getResponse.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return
    response = json.loads(getResponse.text)
    logging.info(getResponse.text)

    for items in response["results"]:
        if feature == "on_prem_hosts":
                storeList.append(items["ids"])


    logging.info("Deleting %d Onprem Hosts", len(storeList))
    for id in storeList:
        response = requests.delete(requestURL + "/api/host_app/v1/"+feature/id, headers = headers)
        if not response.ok:
            logging.error("Failed to delete %s : %d", feature, id)

## Cleans Anycast feature objects
def cleanAnycast(feature, requestURL, headers):
    storeList = []
    getResponse = requests.get(requestURL+"/api/anycast/v1/accm"+feature, headers = headers)
    if not getResponse.ok :
        return
    response = json.loads(getResponse.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return
    response = json.loads(getResponse.text)
    logging.info(getResponse.text)
    print(getResponse.text)

    for items in response["results"]:
        if feature == "ac_configs":
                storeList.append(items["ids"])


    logging.info("Deleting %d Anycast-Configs", len(storeList))
    for id in storeList:
        response = requests.delete(requestURL + "/api/anycast/v1/accm"+feature/id, headers = headers)
        if not response.ok:
            logging.error("Failed to delete Anycast Config %d", id)

# Cleans JOIN Tokens
def cleanJoinTokens(requestURL, headers):
        storeList = []
        getResponse = requests.get(requestURL + "/atlas-host-activation/v1/jointoken", headers=headers)
        if not getResponse.ok:
            return
        response = json.loads(getResponse.text)
        if response.get("results"):
            if len(response["results"]) == 0:
                return
        logging.info(getResponse.text)

        for items in response["results"]:
            id = items["id"].split("/")
            storeList.append(id[2])

        data["id"] = storeList
        logging.info("Deleting the Ids %s", data["id"])

        for id in storeList:
            response = requests.delete(requestURL +"/atlas-host-activation/v1/jointoken/"+id, headers = headers)
            if not response.ok:
                logging.error("Failed to delete the JoinToken %s", id)


# Cleans CDC Flow
def cleanCDCFlow(feature, requestURL, headers):
    storeList = []
    getResponse = requests.get(requestURL+"/api/cdc-flow/v1/display"+feature, headers = headers)
    if not getResponse.ok :
        return
    response = json.loads(getResponse.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return
    response = json.loads(getResponse.text)
    logging.info(getResponse.text)
    print(getResponse.text)

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
        response = requests.delete(requestURL + "/api/cdc-flow/v1/display"+feature/id, headers = headers)
        if not response.ok:
            logging.error("Failed to delete %s with %d", feature, id)


## Cleans Notifications
def cleanNotifications(feature,requestURL, headers):
    ## feature = user_alerts, account_alerts
    storeList = []
    getResponse = requests.get(requestURL+"/atlas-notifications-mailbox/v1/"+feature, headers = headers)
    if not getResponse.ok :
        return
    response = json.loads(getResponse.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return
    response = json.loads(getResponse.text)
    logging.info(getResponse.text)

    for items in response["results"]:
        if feature == "account_alerts":
                storeList.append(items["ids"])

        elif feature == "user_alerts":
            storeList.append(items["id"])

    data["ids"] = storeList
    logging.info("Deleting the Ids %s", data["ids"])

    response = requests.delete( requestURL + "/atlas-notifications-mailbox/v1/"+feature, headers=headers, data=json.dumps(data))
    if not response.ok:
        logging.error("Failed to delete the %s ", feature)


# Cleans CDC Flow
def cleanAtlasTags(requestURL, headers):
    storeList = []
    getResponse = requests.get(requestURL+"/api/atlas-tagging/v2/tags", headers = headers)
    if not getResponse.ok :
        return
    response = json.loads(getResponse.text)
    if response.get("results" ):
        if len(response["results"]) == 0:
            return
    response = json.loads(getResponse.text)
    logging.info(getResponse.text)

    for items in response["results"]:
            storeList.append(items["id"])


    logging.info("Deleting ids %d for tags", len(storeList))
    for id in storeList:
        response = requests.delete(requestURL + "/api/atlas-tagging/v2/tags", headers = headers, data=json.dumps(data))
        if not response.ok:
            logging.error("Failed to delete tag with %d",id)

def main(argv):
    if __name__ == "__main__":

        ### Add relevant Auth Token here
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Token e75e4a08e2ae81230cc1f9b645b2e2a6',
        }

        requestURL = ""

        print("Usage:\n <program> <API TOKEN> <CLUSTER URL>")
        # logging.INFO("Usage: <program> <API TOKEN> <CLUSTER URL>")
        print(len(argv))
        if len(argv) != 2:
            sys.exit("Not enough arguments in the command line")

        headers['Authorization'] = "Token " + argv[0]
        requestURL = argv[1]

        ## Add more features if necessary
        atcfwFeatures = ["security_policies", "redirect_page", "internal_domain_lists", "named_lists", "custom_redirects", "network_lists", "access_codes", "category_filters"]
        atcepFeatures = ["roaming_device_groups", "roaming_devices"]
        onPremFeatures = ["on_prem_hosts", "update_configs"]
        anycastFeatures = ["ac_configs"]
        notificationFeatures = ["user_alerts", "account_alerts"]
        cdcFlowFeatures = ["sources","destinations", "flows", "etl/filters"]

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

main(sys.argv[1:])
