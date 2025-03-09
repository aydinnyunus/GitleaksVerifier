import argparse
import base64
import json
import logging
import re
import subprocess
import sys
from subprocess import CompletedProcess
from typing import List, Dict, Any, Union, Optional

import requests
from colorama import init, Fore, Style


def setup_logger(verbose: bool) -> logging.Logger:
    init()

    logger = logging.getLogger("secret_verifier")
    log_level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(log_level)

    class ColoredFormatter(logging.Formatter):

        FORMATS = {
            logging.DEBUG: Fore.BLUE + "%(message)s" + Style.RESET_ALL,
            logging.INFO: Fore.GREEN + "%(levelname)s: %(message)s" + Style.RESET_ALL,
            logging.WARNING: Fore.YELLOW
            + "%(levelname)s: %(message)s"
            + Style.RESET_ALL,
            logging.ERROR: Fore.RED + "%(levelname)s: %(message)s" + Style.RESET_ALL,
            logging.CRITICAL: Fore.RED
            + Style.BRIGHT
            + "%(levelname)s: %(message)s"
            + Style.RESET_ALL,
        }

        def format(self, record):
            log_fmt = self.FORMATS.get(record.levelno)
            formatter = logging.Formatter(log_fmt)
            return formatter.format(record)

    handler = logging.StreamHandler()
    handler.setFormatter(ColoredFormatter())
    logger.addHandler(handler)

    return logger


def parse_gitleaks_json(json_file: str) -> List[Dict[str, Any]]:
    try:
        with open(json_file) as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Input file '{json_file}' not found")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON format in file '{json_file}'")


def save_results(results: List[Dict[str, Any]], output_file: str) -> None:
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)


def verify_secrets(
    data: List[Dict[str, Any]], logger: logging.Logger, rule_filter: str = None
) -> list[Union[dict[str, Union[Optional[bool], Any]], CompletedProcess[str]]]:

    results = []

    for item in data:
        rule_id = item.get("RuleID")
        secret = item.get("Secret")
        match = item.get("Match")

        result = {"secret": secret, "rule_id": rule_id, "valid": False, "match": match}

        if rule_filter and rule_filter.lower() != rule_id.lower():
            continue

        if not secret:
            logger.warning(f"No secret found for rule {rule_id}")
            continue

        logger.debug(f"Verifying secret for rule: {rule_id}")

        try:
            if rule_id == "generic-api-key":
                if secret.endswith("=="):
                    try:
                        decoded = base64.b64decode(secret).decode("utf-8")
                        logger.info(f"Decoded generic API key: {decoded}")
                        result["valid"] = True
                    except:
                        logger.warn(f"Failed to decode API key: {secret}")
            elif rule_id == "cloudflare-api-key":
                response = requests.get(
                    "https://api.cloudflare.com/client/v4/user/tokens/verify",
                    headers={"Authorization": f"Bearer {secret}"},
                )
                if response.status_code == 200:
                    logger.info("Valid Cloudflare API key")
                    result["valid"] = True
            elif rule_id == "pypi-upload-token":
                response = requests.get(
                    "https://upload.pypi.org/legacy/",
                    headers={"Authorization": f"Basic {secret}"},
                )
                if response.status_code == 200:
                    logger.info("Valid PyPI upload token")
                    result["valid"] = True

            elif rule_id == "shopify-access-token":
                response = requests.get(
                    "https://shopify.com/admin/api/2021-07/products.json",
                    headers={"X-Shopify-Access-Token": secret},
                )
                if response.status_code == 200:
                    logger.info("Valid Shopify access token")
                    result["valid"] = True

            elif rule_id == "openai-api-key":
                response = requests.get(
                    "https://api.openai.com/v1/engines",
                    headers={"Authorization": f"Bearer {secret}"},
                )
                if response.status_code == 200:
                    logger.info("Valid OpenAI API key")
                    result["valid"] = True
            elif rule_id == "npm-access-token":
                response = requests.get(
                    "https://registry.npmjs.org/-/npm/v1/user",
                    headers={"Authorization": f"Bearer {secret}"},
                )
                if response.status_code == 200:
                    logger.info("Valid NPM access token")
                    result["valid"] = True
            elif rule_id == "datadog-access-token":
                response = requests.get(
                    "https://api.datadoghq.com/api/v1/validate",
                    headers={"DD-API-KEY": secret},
                )
                if response.status_code == 200:
                    logger.info("Valid Datadog access token")
                    result["valid"] = True
            elif rule_id == "dropbox-api-token":
                response = requests.post(
                    "https://api.dropboxapi.com/2/users/get_current_account",
                    headers={"Authorization ": f"Bearer {secret}"},
                )
                if response.status_code == 200:
                    logger.info("Valid Dropbox API token")
                    result["valid"] = True
            elif rule_id == "zendesk-secret-key":
                print(
                    f"curl https://<subdomain>.zendesk.com/api/v2/tickets.json -H 'Authorization: Bearer {secret}'"
                )
                result["valid"] = False
            elif rule_id == "algolia-api-key":
                print(
                    f"curl --request GET \
              --url https://<example-app-id>-1.algolianet.com/1/indexes/<example-index> \
              --header 'content-type: application/json' \
              --header 'x-algolia-api-key: {secret}' \
              --header 'x-algolia-application-id: <example-appid>'"
                )
                result["valid"] = False

            # Slack verification
            elif rule_id == "slack-webhook" or rule_id == "slack-webhook-url":
                response = requests.post(match, json={"text": ""})
                if "missing_text_or_fallback_or_attachments" in response.text or "no_text" in response.text:
                    logger.info("Valid Slack webhook")
                    result["valid"] = True

            elif rule_id == "slack-token":
                if secret.startswith(("xoxp-", "xoxb-")):
                    response = requests.post(
                        "https://slack.com/api/auth.test",
                        headers={"Authorization": f"Bearer {secret}"},
                    )
                    if response.status_code == 200:
                        logger.info("Valid Slack token")
                        result["valid"] = True

            # SauceLabs verification
            elif rule_id == "saucelabs":
                username = secret.split(":")[0]
                access_key = secret.split(":")[1]
                response = requests.get(
                    f"https://saucelabs.com/rest/v1/users/{username}",
                    auth=(username, access_key),
                )
                if response.status_code == 200:
                    logger.info("Valid SauceLabs credentials")
                    result["valid"] = True

            # Facebook verification
            elif rule_id == "facebook-app-secret":
                response = requests.get(
                    f"https://graph.facebook.com/oauth/access_token?client_id=ID_HERE&client_secret={secret}"
                )
                if response.status_code == 200:
                    logger.info("Valid Facebook app secret")
                    result["valid"] = True
            elif rule_id == "grafana-cloud-api-token":
                print(
                    f'curl -s -H "Authorization: Bearer {secret}" http://your-grafana-server-url.com/api/user'
                )
                result["valid"] = True

            elif rule_id == "facebook-access-token":
                response = requests.get(
                    f"https://developers.facebook.com/tools/debug/accesstoken/?access_token={secret}"
                )
                if response.status_code == 200:
                    logger.info("Valid Facebook access token")
                    result["valid"] = True
            elif rule_id == "gcp-api-key":
                vulnerable_apis = []
                url = "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=" + secret
                response = requests.get(url, verify=False)
                if response.status_code == 200:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Staticmap API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Staticmap 			|| $2 per 1000 requests")
                elif b"PNG" in response.content:
                    print("API key is not vulnerable for Staticmap API.")
                    print("Reason: Manually check the " + url + " to view the reason.")
                else:
                    print("API key is not vulnerable for Staticmap API.")
                    print("Reason: " + str(response.content))

                url = "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key=" + secret
                response = requests.get(url, verify=False)
                if response.status_code == 200:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Streetview API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Streetview 			|| $7 per 1000 requests")
                elif b"PNG" in response.content:
                    print("API key is not vulnerable for Staticmap API.")
                    print("Reason: Manually check the " + url + " to view the reason.")
                else:
                    print("API key is not vulnerable for Staticmap API.")
                    print("Reason: " + str(response.content))

                url = "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key=" + secret
                response = requests.get(url, verify=False)
                if response.text.find("error_message") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Directions API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Directions 			|| $5 per 1000 requests")
                    vulnerable_apis.append("Directions (Advanced) 	|| $10 per 1000 requests")
                else:
                    print("API key is not vulnerable for Directions API.")
                    print("Reason: " + response.json()["error_message"])

                url = "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=" + secret
                response = requests.get(url, verify=False)
                if response.text.find("error_message") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Geocode API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Geocode 			|| $5 per 1000 requests")
                else:
                    print("API key is not vulnerable for Geocode API.")
                    print("Reason: " + response.json()["error_message"])

                url = "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key=" + secret
                response = requests.get(url, verify=False)
                if response.text.find("error_message") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Distance Matrix API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Distance Matrix 		|| $5 per 1000 elements")
                    vulnerable_apis.append("Distance Matrix (Advanced) 	|| $10 per 1000 elements")
                else:
                    print("API key is not vulnerable for Distance Matrix API.")
                    print("Reason: " + response.json()["error_message"])

                url = "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key=" + secret
                response = requests.get(url, verify=False)
                if response.text.find("error_message") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Find Place From Text API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Find Place From Text 		|| $17 per 1000 elements")
                else:
                    print("API key is not vulnerable for Find Place From Text API.")
                    print("Reason: " + response.json()["error_message"])

                url = "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key=" + secret
                response = requests.get(url, verify=False)
                if response.text.find("error_message") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Autocomplete API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Autocomplete 			|| $2.83 per 1000 requests")
                    vulnerable_apis.append("Autocomplete Per Session 	|| $17 per 1000 requests")
                else:
                    print("API key is not vulnerable for Autocomplete API.")
                    print("Reason: " + response.json()["error_message"])

                url = "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=" + secret
                response = requests.get(url, verify=False)
                if response.text.find("error_message") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Elevation API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Elevation 			|| $5 per 1000 requests")
                else:
                    print("API key is not vulnerable for Elevation API.")
                    print("Reason: " + response.json()["error_message"])

                url = "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=" + secret
                response = requests.get(url, verify=False)
                if response.text.find("errorMessage") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Timezone API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Timezone 			|| $5 per 1000 requests")
                else:
                    print("API key is not vulnerable for Timezone API.")
                    print("Reason: " + response.json()["errorMessage"])

                url = "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key=" + secret
                response = requests.get(url, verify=False)
                if response.text.find("error") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Nearest Roads API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Nearest Roads 		|| $10 per 1000 requests")
                else:
                    print("API key is not vulnerable for Nearest Roads API.")
                    print("Reason: " + response.json()["error"]["message"])

                url = "https://www.googleapis.com/geolocation/v1/geolocate?key=" + secret
                postdata = {'considerIp': 'true'}
                response = requests.post(url, data=postdata, verify=False)
                if response.text.find("error") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Geolocation API! Here is the PoC curl command which can be used from terminal:")
                    print(
                        "curl -i -s -k  -X $'POST' -H $'Host: www.googleapis.com' -H $'Content-Length: 22' --data-binary $'{\"considerIp\": \"true\"}' $'" + url + "'")
                    vulnerable_apis.append("Geolocation 			|| $5 per 1000 requests")
                else:
                    print("API key is not vulnerable for Geolocation API.")
                    print("Reason: " + response.json()["error"]["message"])

                url = "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key=" + secret
                response = requests.get(url, verify=False)
                if response.text.find("error") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Route to Traveled API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Route to Traveled 		|| $10 per 1000 requests")
                else:
                    print("API key is not vulnerable for Route to Traveled API.")
                    print("Reason: " + response.json()["error"]["message"])

                url = "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key=" + secret
                response = requests.get(url, verify=False)
                if response.text.find("error") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Speed Limit-Roads API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Speed Limit-Roads 		|| $20 per 1000 requests")
                else:
                    print("API key is not vulnerable for Speed Limit-Roads API.")

                    print("Reason: " + response.json()["error"]["message"])

                url = "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key=" + secret
                response = requests.get(url, verify=False)
                if response.text.find("error_message") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Place Details API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Place Details 		|| $17 per 1000 requests")
                else:
                    print("API key is not vulnerable for Place Details API.")
                    print("Reason: " + response.json()["error_message"])

                url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key=" + secret
                response = requests.get(url, verify=False)
                if response.text.find("error_message") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Nearby Search-Places API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Nearby Search-Places		|| $32 per 1000 requests")
                else:
                    print("API key is not vulnerable for Nearby Search-Places API.")
                    print("Reason: " + response.json()["error_message"])

                url = "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key=" + secret
                response = requests.get(url, verify=False)
                if response.text.find("error_message") < 0:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Text Search-Places API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Text Search-Places 		|| $32 per 1000 requests")
                else:
                    print("API key is not vulnerable for Text Search-Places API.")
                    print("Reason: " + response.json()["error_message"])

                url = "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key=" + secret
                response = requests.get(url, verify=False, allow_redirects=False)
                if response.status_code == 302:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for Places Photo API! Here is the PoC link which can be used directly via browser:")
                    print(url)
                    vulnerable_apis.append("Places Photo 			|| $7 per 1000 requests")
                else:
                    print("API key is not vulnerable for Places Photo API.")
                    print("Reason: Verbose responses are not enabled for this API, cannot determine the reason.")

                url = "https://fcm.googleapis.com/fcm/send"
                postdata = "{'registration_ids':['ABC']}"
                response = requests.post(url, data=postdata, verify=False,
                                         headers={'Content-Type': 'application/json', 'Authorization': 'key=' + secret})
                if response.status_code == 200:
                    print(
                        "API key is \033[1;31;40mvulnerable\033[0m for FCM API! Here is the PoC curl command which can be used from terminal:")
                    print(
                        "curl --header \"Authorization: key=" + secret + "\" --header Content-Type:\"application/json\" https://fcm.googleapis.com/fcm/send -d '{\"registration_ids\":[\"ABC\"]}'")
                    vulnerable_apis.append("FCM Takeover 			|| https://abss.me/posts/fcm-takeover/")
                else:
                    print("API key is not vulnerable for FCM API.")
                    for lines in response.iter_lines():
                        if (("TITLE") in str(lines)):
                            print("Reason: " + str(lines).split("TITLE")[1].split("<")[0].replace(">", ""))

                if len(vulnerable_apis) > 0:
                    result["valid"] = True

            # Firebase verification
            elif rule_id == "firebase-token":
                response = requests.post(
                    f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken",
                    params={"key": secret},
                )
                if response.status_code == 200:
                    logger.info("Valid Firebase token")
                    result["valid"] = True

            # GitHub verification
            elif rule_id == "github-token" or rule_id == "github-pat":
                response = requests.get(
                    "https://api.github.com/user",
                    headers={"Authorization": f"token {secret}"},
                )
                if response.status_code == 200:
                    logger.info("Valid GitHub token")
                    result["valid"] = True

            elif rule_id == "gitlab-pat":
                response = requests.get(
                    f"https://gitlab.com/api/v4/projects?private_token={secret}"
                )
                if response.status_code == 200:
                    logger.info("Valid Gitlab token")
                    result["valid"] = True
            elif rule_id == "github-client":
                client_id = secret.split(":")[0]
                client_secret = secret.split(":")[1]
                response = requests.get(
                    f"https://api.github.com/users/whatever",
                    params={"client_id": client_id, "client_secret": client_secret},
                )
                if response.status_code == 200:
                    logger.info("Valid GitHub client credentials")
                    result["valid"] = True

            elif rule_id == "github-ssh":
                result = subprocess.run(
                    ["ssh", "-i", secret, "-T", "git@github.com"],
                    capture_output=True,
                    text=True,
                )
                if "successfully authenticated" in result.stderr:
                    logger.info("Valid GitHub SSH key")
                    result["valid"] = True

            elif rule_id == "twilio":
                account_sid = secret.split(":")[0]
                auth_token = secret.split(":")[1]
                response = requests.get(
                    "https://api.twilio.com/2010-04-01/Accounts.json",
                    auth=(account_sid, auth_token),
                )
                if response.status_code == 200:
                    logger.info("Valid Twilio credentials")
                    result["valid"] = True

            elif rule_id == "twitter-api":
                api_key = secret.split(":")[0]
                api_secret = secret.split(":")[1]
                response = requests.post(
                    "https://api.twitter.com/oauth2/token",
                    auth=(api_key, api_secret),
                    data={"grant_type": "client_credentials"},
                )
                if response.status_code == 200:
                    logger.info("Valid Twitter API credentials")
                    result["valid"] = True

            elif rule_id == "twitter-bearer":
                response = requests.get(
                    "https://api.twitter.com/1.1/account_activity/all/subscriptions/count.json",
                    headers={"Authorization": f"Bearer {secret}"},
                )
                if response.status_code == 200:
                    logger.info("Valid Twitter bearer token")
                    result["valid"] = True

            elif rule_id == "hubspot-key":
                response = requests.get(
                    "https://api.hubapi.com/owners/v2/owners",
                    params={"hsecret": secret},
                )
                if response.status_code == 200:
                    logger.info("Valid HubSpot API key")
                    result["valid"] = True

            elif rule_id == "infura-key":
                response = requests.post(
                    f"https://mainnet.infura.io/v3/{secret}",
                    json={
                        "jsonrpc": "2.0",
                        "method": "eth_accounts",
                        "params": [],
                        "id": 1,
                    },
                )
                if response.status_code == 200:
                    logger.info("Valid Infura API key")
                    result["valid"] = True

            elif rule_id == "mailgun-private-api-token":
                response = requests.get(
                    "https://api.mailgun.net/v3/domains", auth=("api", secret)
                )
                if response.status_code == 200:
                    logger.info("Valid Mailgun private API token")
                    result["valid"] = True

            elif rule_id == "mapbox-api-token":
                response = requests.get(
                    f"https://api.mapbox.com/geocoding/v5/mapbox.places/Los%20Angeles.json?access_token={secret}"
                )
                if response.status_code == 200:
                    logger.info("Valid Mapbox API token")
                    result["valid"] = True

            elif rule_id == "new-relic-user-api-key":
                response = requests.get(
                    "https://api.newrelic.com/v2/applications.json",
                    headers={"X-Api-Key": secret},
                )
                if response.status_code == 200:
                    logger.info("Valid New Relic user API key")
                    result["valid"] = True
            elif rule_id == "deviantart-secret":
                response = requests.post(
                    "https://www.deviantart.com/oauth2/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": "ID_HERE",
                        "client_secret": secret,
                    },
                )
                if response.status_code == 200:
                    logger.info("Valid DeviantArt secret")
                    result["valid"] = True
            elif rule_id == "heroku-api-key":
                response = requests.post(
                    "https://api.heroku.com/apps",
                    headers={"Authorization": f"Bearer {secret}"},
                )
                if response.status_code == 200:
                    logger.info("Valid Heroku API key")
                    result["valid"] = True
            elif rule_id == "deviantart-token":
                response = requests.post(
                    "https://www.deviantart.com/api/v1/oauth2/placebo",
                    data={"access_token": secret},
                )
                if response.status_code == 200:
                    logger.info("Valid DeviantArt access token")
                    result["valid"] = True

            elif rule_id == "pendo-key":
                response = requests.get(
                    "https://app.pendo.io/api/v1/feature",
                    headers={"X-Pendo-Integration-Key": secret},
                )
                if response.status_code == 200:
                    logger.info("Valid Pendo integration key")
                    result["valid"] = True

            elif rule_id == "sendgrid-token":
                response = requests.get(
                    "https://api.sendgrid.com/v3/scopes",
                    headers={"Authorization": f"Bearer {secret}"},
                )
                if response.status_code == 200:
                    logger.info("Valid SendGrid API token")
                    result["valid"] = True

            elif rule_id == "square-token":
                if re.match(r"EAAA[a-zA-Z0-9]{60}", secret):
                    response = requests.get(
                        "https://connect.squareup.com/v2/locations",
                        headers={"Authorization": f"Bearer {secret}"},
                    )
                    if response.status_code == 200:
                        logger.info("Valid Square token")
                        result["valid"] = True

            elif rule_id == "contentful-token":
                response = requests.get(
                    f"https://cdn.contentful.com/spaces/SPACE_ID/entries",
                    params={"access_token": secret},
                )
                if response.status_code == 200:
                    logger.info("Valid Contentful token")
                    result["valid"] = True

            elif rule_id == "microsoft-tenant":
                if re.match(r"[0-9a-z\-]{36}", secret):
                    logger.info("Valid Microsoft tenant format")
                    result["valid"] = True

            elif rule_id == "browserstack":
                response = requests.get(
                    "https://api.browserstack.com/automate/plan.json",
                    auth=(secret.split(":")[0], secret.split(":")[1]),
                )
                if response.status_code == 200:
                    logger.info("Valid BrowserStack access key")
                    result["valid"] = True

            elif rule_id == "azure-insights":
                response = requests.get(
                    f"https://api.applicationinsights.io/v1/apps/{secret}/metrics/requests/count",
                    headers={"x-api-key": secret},
                )
                if response.status_code == 200:
                    logger.info("Valid Azure Insights key")
                    result["valid"] = True

            elif rule_id == "cypress-record":
                response = requests.post(
                    "https://api.cypress.io/runs",
                    headers={"x-route-version": "4"},
                    json={"projectId": "project_id", "recordKey": secret},
                )
                if response.status_code == 200:
                    logger.info("Valid Cypress record key")
                    result["valid"] = True

            else:
                logger.warning(
                    f"No specific verification method for rule ID: {rule_id}, secret: {secret}"
                )

        except Exception as e:
            logger.error(f"Error verifying {rule_id}: {str(e)}")

        results.append(result)
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Verify secrets found by gitleaks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("json_file", help="Path to the gitleaks JSON output file")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument("-r", "--rule", help="Filter verification by specific rule ID")
    parser.add_argument(
        "-o",
        "--output",
        help="Output JSON file for verification results",
        default="verification_results.json",
    )
    parser.add_argument(
        "--only-valid",
        action="store_true",
        help="Print only valid secrets",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")

    args = parser.parse_args()

    logger = setup_logger(args.verbose)

    try:
        data = parse_gitleaks_json(args.json_file)
        results = verify_secrets(data, logger, args.rule)

        if args.only_valid:
            results = [result for result in results if result.get("valid")]

        save_results(results, args.output)
        logger.info(f"Results saved to {args.output}")
    except Exception as e:
        logger.error(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
