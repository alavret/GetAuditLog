import argparse
from dotenv import load_dotenv
import requests
import logging
import logging.handlers as handlers
import os.path
import sys
from datetime import datetime, timedelta
from os import environ
import re
import csv
import json
from dataclasses import dataclass
from textwrap import dedent
from http import HTTPStatus

DEFAULT_360_API_URL = "https://api360.yandex.net"
DEFAULT_OAUTH_API_URL = "https://oauth.yandex.ru/token"
LOG_FILE = "get_audit.log"
DEFAULT_DAYS_AGO = 45

EXIT_CODE = 1

logger = logging.getLogger("get_audit_log")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
file_handler = handlers.TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=7, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(console_handler)
logger.addHandler(file_handler)

def arg_parser():
    parser = argparse.ArgumentParser(
        description=dedent(
            """
            Script for downloading audit log records from Yandex 360.

            Define Environment variables or use .env file to set values of those variables:
            OAUTH_TOKEN_ARG - OAuth Token,
            ORGANIZATION_ID_ARG - Organization ID,
            APPLICATION_CLIENT_ID_ARG - WEB Application ClientID,
            APPLICATION_CLIENT_SECRET_ARG - WEB Application secret

            For example:
            OAUTH_TOKEN_ARG = "AgAAgfAAAAD4beAkEsWrefhNeyN1TVYjGT1k",
            ORGANIZATION_ID_ARG =1 23
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    def argument_range(value: str) -> int:
        try:
            if int(value) < 0 or int(value) > 90:
                raise argparse.ArgumentTypeError(
                    f"{value} is invalid. Valid values in range: [0, 90]"
                )
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{value}' is not int value")
        return int(value)

    parser.add_argument(
        "--date-ago",
        help="Number of days ago to search and download audit log records [0, 90]",
        type=argument_range,
        required=False,
    )
    return parser

def main():
    parsr = arg_parser()
    try:
        args = parsr.parse_args()
    except Exception as e:
        logger.exception(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

    try:
        settings = get_settings()
    except ValueError:
        logging.error(f"ERROR: The value of ORGANIZATION_ID_ARG must be an integer.")
        sys.exit(EXIT_CODE)
    except KeyError as key:
        logger.error(f"ERROR: Required environment vars not provided: {key}")
        parsr.print_usage()
        sys.exit(EXIT_CODE)

    if args.date_ago is None: 
        logger.warning("Command line argument 'date_ago' is not set. Download all records.")
        args.date_ago = DEFAULT_DAYS_AGO

    date_ago = args.date_ago
    records = fetch_audit_logs(settings, date_ago=date_ago)

    #print(records)
    if records:
        file_name = f'{settings.output_file.split(".")[0]}_{datetime.now().strftime("%y-%m-%d_%H-%M-%S")}.csv'
        WriteToFile(records, file_name)
        logger.info(f"{len(records)} audit records written to {settings.output_file}")


    logger.info("Sript finished.")

def get_settings():
    settings = SettingParams (
        oauth_token = os.environ.get("OAUTH_TOKEN_ARG"),
        organization_id = int(os.environ.get("ORGANIZATION_ID_ARG")),
        output_file = os.environ.get("OUTPUT_FILE_NAME"),
    )
    return settings

def fetch_audit_logs(settings: "SettingParams", date_ago: int):
    day_last_check = (datetime.now().replace(hour=0, minute=0, second=0) - timedelta(days=date_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    log_records = []

    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.organization_id}/audit_log/mail"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}

    params = {
        "pageSize": 100,
        "afterDate": day_last_check,
    }
    
    while True:           
        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during GET request: {response.status_code}")
                return
            temp_list = response.json()["events"]

            logger.debug(f'Received {len(temp_list)} records, from {temp_list[-1]["date"]} to {temp_list[0]["date"]}')
            for entry in temp_list:
                log_records.append(parse_to_dict(entry))
            #log_records.extend(temp_list)
            if response.json()["nextPageToken"] == "":
                break
            else:
                params["pageToken"] = response.json()["nextPageToken"]
        except requests.exceptions.RequestException as err:
            logger.error(f"Error during GET request: {err}")
            return
        
    return log_records

def WriteToFile(data, filename):
    with open(filename, 'w', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=data[0].keys(), delimiter=';')

        writer.writeheader()
        writer.writerows(data)

def parse_to_dict(data: dict):
    #obj = json.dumps(data)
    d = {}
    d["eventType"] = data.get("eventType",'')
    d["date"] = data.get("date").replace('T', ' ').replace('Z', '')
    d["userLogin"] = data.get("userLogin",'')
    d["userName"] = data.get("userName",'')
    d["from"] = data.get("from",'')
    d["to"] = data.get("to",'')
    d["subject"] = data.get("subject",'')
    d["folderName"] = data.get("folderName",'')
    d["folderType"] = data.get("folderType",'')
    d["labels"] = data.get("labels",[])
    d["orgId"] = data.get("orgId")
    d["requestId"] = data.get("requestId",'')
    d["clientIp"] = data.get("clientIp",'')
    d["userUid"] = data.get("userUid",'')
    d["msgId"] = data.get("msgId",'')
    d["uniqId"] = data.get("uniqId",'')
    d["source"] = data.get("source",'')
    d["mid"] = data.get("mid",'')
    d["cc"] = data.get("cc",'')
    d["bcc"] = data.get("bcc",'')
    d["destMid"] = data.get("destMid",'')
    d["actorUid"] = data.get("actorUid",'')
    return d
    
@dataclass
class SettingParams:
    oauth_token: str
    organization_id: int
    output_file: str


if __name__ == "__main__":

    denv_path = os.path.join(os.path.dirname(__file__), '.env')

    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path,verbose=True, override=True)

    try:
        main()
    except Exception as exp:
        logging.exception(exp)
        sys.exit(EXIT_CODE)