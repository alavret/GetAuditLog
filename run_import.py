import argparse
from dotenv import load_dotenv
import requests
import logging
import logging.handlers as handlers
import os.path
import sys
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from os import environ
import re
import csv
import json
from dataclasses import dataclass
from textwrap import dedent
from http import HTTPStatus
from asyncio import run, wait_for
from collections import namedtuple
from email.message import Message
from email.parser import BytesHeaderParser, BytesParser
from email.header import decode_header
from typing import Collection
import email
import asyncio
import concurrent.futures
import aioimaplib
from typing import Optional


DEFAULT_IMAP_SERVER = "imap.yandex.ru"
DEFAULT_IMAP_PORT = 993
DEFAULT_360_API_URL = "https://api360.yandex.net"
DEFAULT_OAUTH_API_URL = "https://oauth.yandex.ru/token"
LOG_FILE = "get_audit.log"
DEFAULT_DAYS_AGO = 45
FILTERED_EVENTS = ["message_receive", "message_purge", "message_trash"]
FILTERED_MAILBOXES = ["alavret@yandry.ru"]

ID_HEADER_SET = {'Content-Type', 'From', 'To', 'Cc', 'Bcc', 'Date', 'Subject',
                                   'Message-ID', 'In-Reply-To', 'References', 'X-Yandex-Fwd', 'Return-Path', 'X-Yandex-Spam', "X-Mailer"}
FETCH_MESSAGE_DATA_UID = re.compile(rb'.*UID (?P<uid>\d+).*')
FETCH_MESSAGE_DATA_SEQNUM = re.compile(rb'(?P<seqnum>\d+) FETCH.*')
FETCH_MESSAGE_DATA_FLAGS  = re.compile(rb'.*FLAGS \((?P<flags>.*?)\).*')
MessageAttributes = namedtuple('MessageAttributes', 'uid flags sequence_number')

EXIT_CODE = 1

logger = logging.getLogger("get_audit_log")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
file_handler = handlers.TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=7, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(console_handler)
logger.addHandler(file_handler)

@dataclass
class SettingParams:
    oauth_token: str
    organization_id: int
    output_file: str
    application_client_id: str
    application_client_secret: str
    
def main():

    try:
        settings = get_settings()
    except ValueError:
        logging.error(f"ERROR: The value of ORGANIZATION_ID_ARG must be an integer.")
        sys.exit(EXIT_CODE)
    except KeyError as key:
        logger.error(f"ERROR: Required environment vars not provided: {key}")
        # parsr.print_usage()
        sys.exit(EXIT_CODE)

    imap_messages = {}
    users = get_all_users(settings)
    if not users:
        logger.error("No users found in Yandex 360. Exiting.")
        sys.exit(EXIT_CODE)

    if not FILTERED_MAILBOXES:
        logger.error("Param FILTERED_MAILBOXES is empty. Exiting.")
        sys.exit(EXIT_CODE)

    filtered_uids = []
    filtered_aliases = [u.split("@")[0] for u in FILTERED_MAILBOXES]
    for user in users:
        aliases = []
        aliases = [u["value"].split("@")[0] for u in user["contacts"] if u["type"] == "email"]
        for alias in aliases:
            if alias in filtered_aliases:
                filtered_uids.append(user["id"])
    
    if not filtered_uids:
        logger.error("Didnn't find any users with email addresses in FILTERED_MAILBOXES. Exiting.")
        sys.exit(EXIT_CODE)

    if len(filtered_uids) != len(FILTERED_MAILBOXES):
        logger.error("Some users with email addresses in FILTERED_MAILBOXES were not found. Exiting.")
        sys.exit(EXIT_CODE)

    logger.info(f"FILTERED_MAILBOXES email ids: {filtered_uids}.")

    first_date =  datetime.now() + relativedelta(months = -1, day = 1, hour = 0, minute = 0, second = 0) + relativedelta(days = -1)
    last_date = datetime.now() + relativedelta(day = 2, hour = 0, minute = 0, second = 0)
    logger.info(f"Search data from {first_date.strftime("%Y-%m-%d")} to {last_date.strftime("%Y-%m-%d")}.")

    records = fetch_audit_logs(settings, filtered_uids, first_date, last_date)
    file_name = f'raw_search_result_{datetime.now().strftime("%y-%m-%d_%H-%M-%S")}.csv'
    #WriteToFile(records, file_name)
    #records = FilterEvents(records)
    target_records = []
    #print(records)
    for user in FILTERED_MAILBOXES:
        token = get_user_token(user, settings)
        if token:
            asyncio.run(get_imap_messages(user, token, first_date, last_date, imap_messages))
            for k, v in imap_messages.items():
                logger.debug(f'{k} - {v}\n')
            logger.debug('\n')
            logger.debug(imap_messages)
        for record in records:
            logger.debug(f"Processing record: {record} for user: {user}")
            if record["userLogin"].split("@")[0] == user.split("@")[0] and record["msgId"]:
                logger.debug(f"Found record: {record} for alias: {record["userLogin"].split("@")[0]}")
                d = {}
                d["date"] = record["date"][0:-4]
                imap_data = imap_messages.get(record["msgId"],'')
                if imap_data:
                    d["from"] = imap_data['from']
                    if imap_data['folder'] == "Trash":
                        d["deleted"] = "Удалено"
                    else:
                        d["deleted"] = "Не удалено"
                else:
                    d["from"] = record["from"]
                    
                    d["deleted"] = "Удалено"

                d["subject"] = record["subject"]
                d["msgId"] = record["msgId"]
                target_records.append(d)

    last_day_of_prev_month = datetime.now() + relativedelta(months=-1, day=1)
    check_value = last_day_of_prev_month.strftime("%Y-%m")
    last_month_records = []
    for record in target_records:
        if record["date"][:7] == check_value:
            last_month_records.append(record)

    #print(last_month_records)
    
    if last_month_records:

        file_name = f'{settings.output_file.split(".")[0]}_{datetime.now().strftime("%y-%m-%d_%H-%M-%S")}.csv'
        write_to_ifarma_file(last_month_records, file_name)

        logger.info(f"{len(last_month_records)} audit records written to {file_name}")


    logger.info("Sript finished.")

def get_all_users(settings, file=False):
    """
    Get all users of the organisation and write info about them in file.
    """
    logger.info("Getting all users of the organisation...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.organization_id}/users?perPage=100"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    try:
        response = requests.get(url, headers=headers)
        if response.ok:
                users = response.json()['users']
                for i in range(2, response.json()["pages"] + 1):
                    response = requests.get(f"{url}&page={i}", headers=headers)
                    if response.ok:
                        users.extend(response.json()['users'])

    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
    
    logger.info(f"{len(users)} users found.")
    return users

def FilterEvents(events: list) -> list:
    filtered_events = []
    for event in events:
        if event["eventType"] in FILTERED_EVENTS and event["userLogin"] in FILTERED_MAILBOXES:
            filtered_events.append(event)
    return filtered_events


def get_settings():
    settings = SettingParams (
        oauth_token = os.environ.get("OAUTH_TOKEN_ARG"),
        organization_id = int(os.environ.get("ORGANIZATION_ID_ARG")),
        output_file = os.environ.get("OUTPUT_FILE_NAME"),
        application_client_id = os.environ.get("APPLICATION_CLIENT_ID_ARG"),
        application_client_secret = os.environ.get("APPLICATION_CLIENT_SECRET_ARG"),

    )
    return settings

def fetch_audit_logs(settings: "SettingParams", filtered_uids: list, first_date: datetime, last_date: datetime):
    # last_date =  datetime.now() + relativedelta(months = -1, day = 1) + relativedelta(days = -1)
    # first_date = datetime.now() + relativedelta(day = 2)
    final_first_date = (first_date.replace(day=1, hour=0, minute=0, second=0)).strftime("%Y-%m-%dT%H:%M:%SZ")
    final_last_date = (last_date.replace(day=1, hour=0, minute=0, second=0)).strftime("%Y-%m-%dT%H:%M:%SZ")
    #day_last_check = (datetime.now().replace(hour=0, minute=0, second=0) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    log_records = []

    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.organization_id}/audit_log/mail"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}

    params = {
        "pageSize": 100,
        "afterDate": final_first_date,
        "beforeDate": final_last_date,
        "includeUids": filtered_uids,
        "types": FILTERED_EVENTS
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

def write_to_ifarma_file(data, filename):
    field_names = ["Дата-время", "От кого", "Тема", "Идентификатор", "Удалено да/нет"]
    prepared_data = []
    for entry in data:
        prepared_data.append({
            "Дата-время": entry["date"],
            "От кого": entry["from"],
            "Тема": entry["subject"],
            "Идентификатор": entry["msgId"],
            "Удалено да/нет": entry["deleted"]
        })
    with open(filename, 'w', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=field_names, delimiter=';')

        writer.writeheader()
        writer.writerows(prepared_data)

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
    


def log_error(info="Error"):
    logger.error(info)

def log_info(info="Info"):
    logger.info(info)

def log_debug(info="Debug"):
    logger.debug(info)

def get_user_token(user_mail: str, settings: "SettingParams"):
    logger.debug(f"Getting user token for {user_mail}")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": settings.application_client_id,
        "client_secret": settings.application_client_secret,
        "subject_token": user_mail,
        "subject_token_type": "urn:yandex:params:oauth:token-type:email",
    }
    response = requests.post(url=DEFAULT_OAUTH_API_URL, headers=headers, data=data)
    logger.debug(f"User token for {user_mail} received")
    return response.json()["access_token"]
    if response.status_code != HTTPStatus.OK.value:
        logger.exception(f"Error during GET request: {response.status_code}")
    return ''

async def get_imap_messages(user_mail: str, token: str, start_date: datetime, end_date: datetime, imap_messages: dict):
    message_dict = {}
    loop = asyncio.get_running_loop()
    today = datetime.now() 
    # date_days_ago = today - timedelta(days=days_ago)
    search_criteria = f'(SINCE {start_date.strftime("%d-%b-%Y")}) BEFORE {end_date.strftime("%d-%b-%Y")}'
    with concurrent.futures.ThreadPoolExecutor() as pool:
        logger.debug(f"Connect to IMAP server for {user_mail}")
        await loop.run_in_executor(pool, log_debug, f"Connect to IMAP server for {user_mail}")
    try:
        imap_connector = aioimaplib.IMAP4_SSL(host=DEFAULT_IMAP_SERVER, port=DEFAULT_IMAP_PORT)
        imap_connector = aioimaplib.IMAP4_SSL(host=DEFAULT_IMAP_SERVER, port=DEFAULT_IMAP_PORT)
        await imap_connector.wait_hello_from_server()
        await imap_connector.xoauth2(user=user_mail, token=token)
        with concurrent.futures.ThreadPoolExecutor() as pool:
            await loop.run_in_executor(pool, log_debug, f"Connect to IMAP server for {user_mail} successful")
        status, folders = await imap_connector.list('""', "*")
        folders = [map_folder(folder) for folder in folders if map_folder(folder)]
        for folder in folders:
            with concurrent.futures.ThreadPoolExecutor() as pool:
                await loop.run_in_executor(pool, log_debug, f"Get messages from {folder}")
            await imap_connector.select(folder)
  
            response = await imap_connector.search(search_criteria)
            if response.result == 'OK':
                if len(response.lines[0]) > 0:
                    for num in response.lines[0].split():
                        message_dict = {}
                        response = await imap_connector.fetch(int(num), '(UID FLAGS BODY.PEEK[HEADER.FIELDS (%s)])' % ' '.join(ID_HEADER_SET))
                        if response.result == 'OK':
                            for i in range(0, len(response.lines) - 1, 3):
                                fetch_command_without_literal = b'%s %s' % (response.lines[i], response.lines[i + 2])

                                uid = int(FETCH_MESSAGE_DATA_UID.match(fetch_command_without_literal).group('uid'))
                                flags = FETCH_MESSAGE_DATA_FLAGS.match(fetch_command_without_literal).group('flags')
                                seqnum = FETCH_MESSAGE_DATA_SEQNUM.match(fetch_command_without_literal).group('seqnum')
                                # these attributes could be used for local state management
                                message_attrs = MessageAttributes(uid, flags, seqnum)
                                message_dict["uid"] = uid
                                message_dict["flags"] = flags.decode("ascii")
                                message_dict["seqnum"] = int(seqnum.decode("ascii"))
                                message_dict["folder"] = folder
                                #print(message_attrs)

                                # uid fetch always includes the UID of the last message in the mailbox
                                # cf https://tools.ietf.org/html/rfc3501#page-61
                                message_headers = BytesHeaderParser().parsebytes(response.lines[i + 1])
                                for header in message_headers.keys():
                                    decoded_to_intermediate = decode_header(message_headers[header])
                                    header_value = []
                                    for s in decoded_to_intermediate:
                                        if s[1] is not None:
                                            header_value.append(s[0].decode(s[1]))
                                        else:
                                            if isinstance(s[0], (bytes, bytearray)):
                                                header_value.append(s[0].decode("ascii").strip())
                                            else:
                                                header_value.append(s[0])
                                    with concurrent.futures.ThreadPoolExecutor() as pool:
                                        await loop.run_in_executor(pool, log_debug, f'{header}: {" ".join(header_value) if len(header_value) > 1 else header_value[0]}')
                                    #print(f'{header}: {" ".join(header_value.split()) if len(header_value) > 1 else header_value[0]}')
                                    message_dict[header.lower()] = f'{" ".join(header_value) if len(header_value) > 1 else header_value[0]}'
                                    # if header.lower() == "from":
                                    #     if "???" in message_dict[header.lower()]:
                                    #         logger.debug(f"{message_dict[header.lower()]}")
                                    
                        imap_messages[message_dict["message-id"]] = message_dict
            else:
                continue

    except Exception as e:
        with concurrent.futures.ThreadPoolExecutor() as pool:
            await loop.run_in_executor(pool, log_debug, f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        #logger.exception(exp)       
    return imap_messages

def map_folder(folder: Optional[bytes]) -> Optional[str]:
    if not folder or folder == b"LIST Completed.":
        return None
    valid = folder.decode("ascii").split('"|"')[-1].strip().strip('""')
    return f'"{valid}"'

if __name__ == "__main__":

    denv_path = os.path.join(os.path.dirname(__file__), '.env')

    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path,verbose=True, override=True)

    try:
        main()
    except Exception as exp:
        logging.exception(exp)
        sys.exit(EXIT_CODE)