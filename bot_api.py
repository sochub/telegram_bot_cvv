#! /usr/bin/python
# coding:utf-8

import json
import requests
import time
import boto3
from boto3.dynamodb.conditions import Key

# Configuration for TELEGRAM

conf = {
    "telegram_chat_id": "",  #telegram chat id
    "telegram_token": "",  #telegram api-token
    "up_time": 1,  #time search vuls in hours
}

### DONE CONFIG TELEGRAM

# DynamoDB configuration
DynamoDBTableName = "" #your dynamodb table name
Primary_Column_Name = 'CVE'
Primary_Key = 1
columns=["Details","Severity", "References"]
client = boto3.client('dynamodb')
DB = boto3.resource('dynamodb')
table = DB.Table(DynamoDBTableName)

### DONE CONFIG DYNAMODB

#put cve into dynamodb.
def putToDynamo(ID, DETAILS, SEVERITY, vulUrl):
    try:
        response = table.put_item(
            Item={
                Primary_Column_Name:ID,
                columns[0]: DETAILS,
                columns[1]: SEVERITY,
                columns[2]: vulUrl
                    }
                )
    except Exception as e:
        exit("Errot putting into DynamoDB" + str(e))

#check cve into dynamodb.
def queryToDynamo(ID):
    try:
        dynamodb_client = boto3.client('dynamodb')
        response = table.get_item(
            Key={
                Primary_Column_Name:ID
            }
        )
        if 'Item' in response:
            return "Reported"
        else:
            return "NoReported"
    except Exception as e:
        exit("error trying to get cve from dynamodb")

#send to telegram channel.
def SendToTelegram(
    ID=None, 
    DETAILS=None, 
    SEVERITY=None, 
    vulUrl=None
    ):

    token = conf["telegram_token"]
    
    if SEVERITY == 'HIGH':
        CODE = '\U0001F534'
    else: 
        CODE = '\U0001F7E1'

    if token is not None:
        text =  "\U000026A0 *CVE*: {id}\n {code}*Severity*: {severity}\n \U00002754 *Details*: {details}\n \U00002622 *References*: {references}\n".format(
            id=ID,
            details=DETAILS,
            severity=SEVERITY,
            references=vulUrl,
            code=CODE)

        url = "https://api.telegram.org/bot{token}/sendMessage".format(token=token)
        alert = text.replace('\t', '')
        keyboard = {"inline_keyboard": [[{"text":"more details", "url":"https://nvd.nist.gov/vuln/detail/"+ID}]]}
        key = json.JSONEncoder().encode(keyboard)
        params = {'chat_id': conf["telegram_chat_id"], 'text': alert, 'parse_mode': 'Markdown', 'reply_markup': key}
        response = requests.post(url, data=params)

#get cve from NVD api. 
def get_cve_critical(up_time):
    api = "https://services.nvd.nist.gov/rest/json/cves/1.0?cvssV3Severity=CRITICAL&resultsPerPage=2000&index=0&modStartDate=" + up_time.replace("+","%2b")
    print(api)
    data = []
    try:
        r = requests.get(api)
        if r.status_code == 200:
            for item in r.json()["result"]["CVE_Items"]:
                data.append(item)
            if data:
                return data
        else:
            print(r.status_code)
    except Exception as e:
        exit("Errot to get CVE list--" + str(e))

#main function to start the reporting. 
def main(event, context):
    result = get_cve_critical(time.strftime("%Y-%m-%dT%X:000 UTC+08:00", time.localtime(time.time()-60*60*conf["up_time"])))
    if result:
        for vuls in result:
            ID = vuls['cve']['CVE_data_meta']['ID']
            DETAILS = vuls['cve']['description']['description_data'][0]['value']
            SEVERITY = vuls['impact']['baseMetricV2']['severity']
            vulUrl = vuls['cve']['references']['reference_data'][0]['url']
            print(ID + ": " + queryToDynamo(ID))
            if queryToDynamo(ID) == 'NoReported':
                putToDynamo(ID, DETAILS, SEVERITY, vulUrl)
                SendToTelegram(ID, DETAILS, SEVERITY, vulUrl)
    else:
        print("No new CVE to report")
        
if __name__ == '__main__':
    main()
