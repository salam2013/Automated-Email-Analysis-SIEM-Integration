import os

import imaplib

import email

from email.header import decode_header

import time

import requests

import socket

import json

import re

import base64

from dotenv import load_dotenv



# Do not forget, we are loading our secrets from our .env, so first we load the secrets.



load_dotenv()



EMAIL_USER = os.getenv('EMAIL_USER')

EMAIL_PASS = os.getenv('EMAIL_PASS')

VT_API_KEY = os.getenv('VT_API_KEY')

SPLUNK_TOKEN = os.getenv('SPLUNK_TOKEN')

SPLUNK_URL = os.getenv('SPLUNK_URL')



IMAP_SERVER = 'imap.gmail.com'

FOLDERS = ['INBOX', '[Gmail]/Spam'] # We are telling our script to read both inbox and Spam folder

CHECK_INTERVAL = 4 * 60  # This means python will read the inbox after every 4 minutes 



seen_uids = set()



def decode_mime(s):

    if not s:

        return ""

    decoded_parts = decode_header(s)

    return ''.join(

        str(part[0], part[1] or 'utf-8') if isinstance(part[0], bytes) else str(part[0])

        for part in decoded_parts

    )



def extract_links(text):

    return re.findall(r'https?://\S+', text or "")



def vt_scan_url(url):

    try:

        headers = {"x-apikey": VT_API_KEY}

        res = requests.post('https://www.virustotal.com/api/v3/urls', data=f"url={url}", headers=headers)

        if res.status_code != 200:

            return {"error": f"submit failed: {res.status_code}"}



        analysis_id = res.json()["data"]["id"]

        time.sleep(15)  # Wait for VT analysis



        res2 = requests.get(f'https://www.virustotal.com/api/v3/analyses/{analysis_id}', headers=headers)

        if res2.status_code != 200:

            return {"error": f"analysis fetch failed: {res2.status_code}"}



        result = res2.json()

        stats = result.get("data", {}).get("attributes", {}).get("stats", {})

        return {

            "malicious": stats.get("malicious", 0),

            "suspicious": stats.get("suspicious", 0),

            "harmless": stats.get("harmless", 0),

            "analysis_id": analysis_id

        }

    except Exception as e:

        return {"error": str(e)}



def send_to_splunk(event):

    payload = {

        "time": int(time.time()),

        "host": socket.gethostname(),

        "source": "email_monitor",

        "sourcetype": "email_event",

        "event": event

    }

    headers = {

        "Authorization": f"Splunk {SPLUNK_TOKEN}",

        "Content-Type": "application/json"

    }

    try:

        res = requests.post(SPLUNK_URL, headers=headers, data=json.dumps(payload))

        if res.status_code == 200:

            print("BNS Event sent to Splunk")

        else:

            print(f" Splunk HEC error: {res.status_code} - {res.text}")

    except Exception as e:

        print("Failed to send to Splunk:", e)



def process_email(msg):

    email_data = {

        "from": decode_mime(msg.get("From")),

        "to": decode_mime(msg.get("To")),

        "subject": decode_mime(msg.get("Subject")),

        "date": msg.get("Date"),

        "attachments": [],

        "links": [],

        "vt_results": [],

        "body": ""

    }



    for part in msg.walk():

        content_type = part.get_content_type()

        content_disposition = str(part.get("Content-Disposition"))



        if content_type == "text/plain" and "attachment" not in content_disposition:

            charset = part.get_content_charset() or "utf-8"

            try:

                body = part.get_payload(decode=True).decode(charset, errors="ignore")

                email_data["body"] = body

            except:

                continue



        if part.get_filename():

            filename = decode_mime(part.get_filename())

            payload = part.get_payload(decode=True)

            if filename and payload:

                b64_content = base64.b64encode(payload).decode('utf-8')

                email_data["attachments"].append({

                    "filename": filename,

                    "content_base64": b64_content,

                    "content_type": content_type

                })



    links = extract_links(email_data["body"])

    email_data["links"] = links



    for link in links:

        print(f"Scanning link: {link}")

        vt_result = vt_scan_url(link)

        email_data["vt_results"].append({

            "url": link,

            "result": vt_result

        })



    return email_data



def main():

    while True:

        try:

            mail = imaplib.IMAP4_SSL(IMAP_SERVER)

            mail.login(EMAIL_USER, EMAIL_PASS)



            for folder in FOLDERS:

                print(f" Checking folder: {folder}")

                mail.select(folder)

                status, messages = mail.search(None, 'ALL')

                if status != "OK":

                    print(" Error fetching messages.")

                    continue



                for num in messages[0].split():

                    typ, msg_data = mail.fetch(num, '(RFC822 UID)')

                    if typ != "OK":

                        continue



                    raw_email = msg_data[0][1]

                    uid_line = msg_data[0][0].decode()

                    match = re.search(r'UID (\d+)', uid_line)

                    uid = match.group(1) if match else num.decode()



                    if uid in seen_uids:

                        continue

                    seen_uids.add(uid)



                    msg = email.message_from_bytes(raw_email)

                    print(f" Email: {decode_mime(msg.get('Subject'))}")

                    event = process_email(msg)

                    send_to_splunk(event)



            mail.logout()

        except Exception as e:

            print("Main loop error:", e)



        print(f"Sleeping for {CHECK_INTERVAL // 60} minutes...\n")

        time.sleep(CHECK_INTERVAL)



if __name__ == "__main__":

    main()

