#!/usr/bin/python3
import sys
import os
import time
from datetime import datetime
import requests
from urllib.parse import quote_plus
import hashlib
import json
#setting up colored output
from colorama import init, Fore, Back, Style
init()

def get_api_key():
    path_ = sys.argv[0].replace(sys.argv[0].split("/")[-1], "")
    with open(f"{path_}api-key.txt", "r") as f:
        for row in f:
            if "virus_total" in row:
                if row.split(":")[1] == "":
                    api_key = input("insert your api key here please or insert the key in the 'api-key.txt' file following the correct structure: ")
                else:
                    api_key = row.split(":")[1]
    return api_key

class Ioc:
    mal_score = 0
    id = ""

    def __init__(self, ioc_type, ioc_value):
        self.type = ioc_type    #type of ioc
        self.value = ioc_value  #the actual ioc
        
        if self.type == "url" and self.value[-1] != "/":
                self.value = self.value + "/"
                self.hash = self.sha256Generator()
        elif self.type == "file": #hash of the data to analyze
            self.hash = self.file_sha256Generator()
        elif self.type == "hash":
            self.hash = self.value
        else:
            self.hash = self.sha256Generator()

    #generate sha256 of the input file
    def file_sha256Generator(self):
        with open(self.value, "rb") as file:
            data = file.read()
            sha256 = hashlib.sha256()
            sha256.update(data)
            hash = sha256.hexdigest()
            return hash

    #generate sha256 of a string
    def sha256Generator(self):
        string_bytes = self.value.encode('utf-8')
        hash_object = hashlib.sha256()
        hash_object.update(string_bytes)
        return hash_object.hexdigest()

    #PREATTY PRINT FUNCTIONS BELOW
    def preatty_print(self, jsonResponse_, ioc):
        if ioc.type == "domain":
            print(Back.WHITE + Fore.GREEN + f"analyzing domain: {jsonResponse_['data']['id']}" + Style.RESET_ALL)
            for i in jsonResponse_['data']['attributes']:
                if i == "last_analysis_results":
                    pass
                elif i in (["last_analysis_date", "last_modification_date", "last_https_certificate_date"]):
                    print(Back.BLACK + f"{i}: " + Style.RESET_ALL + f"{datetime.fromtimestamp(jsonResponse_['data']['attributes'][i])}")
                elif i == "total_votes":
                    print(Fore.RED + f"{i}: " + f"{jsonResponse_['data']['attributes'][i]}" + Style.RESET_ALL)
                    for k in jsonResponse_['data']['attributes'][i]:
                        self.mal_score += jsonResponse_['data']['attributes'][i][k]
                elif i == "whois":
                    out = str(jsonResponse_['data']['attributes'][i]).replace('\n', '\n\t')
                    print(Back.BLACK + f"{i}:" + Style.RESET_ALL + "\n\t" + f"{out}")
                else:
                    print(Back.BLACK + f"{i}: " + Style.RESET_ALL + f"{json.dumps(jsonResponse_['data']['attributes'][i], indent=4)}")            
            print()

        elif ioc.type == "file":
            c = 0
            try:
                #printing some basic data
                print(Back.WHITE + Fore.GREEN+ f"analyzed file (meaningful name) : {jsonResponse_['data']['attributes']['meaningful_name']}" + Style.RESET_ALL)
                print(f"malicious scorereputation (the lower the better ^-^): {jsonResponse_['data']['attributes']['reputation']}")
                print(f"type_description: {jsonResponse_['data']['attributes']['type_description']}")
                print(f"sha256: {jsonResponse_['data']['attributes']['sha256']}")

                #known names of the file
                print(f"\nother known name: ")
                for i in jsonResponse_['data']['attributes']['names']:
                    print(f"    {i}")

                #analysis statistics
                print("\nlast analysis stats: ")
                for i in jsonResponse_['data']['attributes']['last_analysis_stats']:
                    if i == "malicious":
                        print(Fore.RED + f"    {i}: {jsonResponse_['data']['attributes']['last_analysis_stats'][i]}" + Style.RESET_ALL)
                    else:
                        print(f"    {i}: {jsonResponse_['data']['attributes']['last_analysis_stats'][i]}")

                for k in jsonResponse_['data']['attributes']['total_votes']:
                    self.mal_score += jsonResponse_['data']['attributes']['total_votes'][k]

                #vendor data
                if self.mal_score != 0:
                    print("\nVendors who found this malicious file: ")
                    try:
                        for vendor in jsonResponse_['data']['attributes']['last_analysis_results']:
                            if jsonResponse_['data']['attributes']['last_analysis_results'][vendor]['result']:
                                print(f"{jsonResponse_['data']['attributes']['last_analysis_results'][vendor]}")
                    except:
                        print("[!]error: no vendor availale")

                print()
            except:
                print("data could not be extracted in a clean json way.. sorry not sorry :D\nFOLLOWING WITH THE JSON RAW:\n")
                return json.dumps(jsonResponse_, indent=4)

        elif ioc.type == "url":
            print(Back.WHITE + Fore.GREEN + f"analyzing url: {jsonResponse_['data']['attributes']['url']}" + Style.RESET_ALL)
            for i in jsonResponse_['data']['attributes']:
                if i == "last_analysis_results":
                    pass
                elif i in (["last_analysis_date", "last_modification_date", "last_submission_date", "first_submission_date"]):
                    print(Back.BLACK + f"{i}: " + Style.RESET_ALL + f"{datetime.fromtimestamp(jsonResponse_['data']['attributes'][i])}")
                elif i == "total_votes":
                    print(Fore.RED + f"{i}: " + f"{jsonResponse_['data']['attributes'][i]}" + Style.RESET_ALL)
                    for k in jsonResponse_['data']['attributes'][i]:
                        self.mal_score += jsonResponse_['data']['attributes'][i][k]
                else:
                    print(Back.BLACK + f"{i}: " + Style.RESET_ALL + f"{jsonResponse_['data']['attributes'][i]}")

        elif ioc.type == "ip":
            print(Back.WHITE + Fore.GREEN + f"analyzing ip: {jsonResponse_['data']['id']}" + Style.RESET_ALL)
            for i in jsonResponse_['data']['attributes']:
                if i == "last_analysis_results":
                    pass
                elif i in (["last_analysis_date", "last_modification_date"]):
                    print(Back.BLACK + f"{i}: " + Style.RESET_ALL + f"{datetime.fromtimestamp(jsonResponse_['data']['attributes'][i])}")
                elif i == "total_votes":
                    print(Fore.RED + f"{i}: " + f"{jsonResponse_['data']['attributes'][i]}" + Style.RESET_ALL)
                    for k in jsonResponse_['data']['attributes'][i]:
                        self.mal_score += jsonResponse_['data']['attributes'][i][k]
                else:
                    print(Back.BLACK + f"{i}: " + Style.RESET_ALL + f"{json.dumps(jsonResponse_['data']['attributes'][i], indent=4)}")
        
        else:
            print("Malicious score: " + str(jsonResponse_["data"]["attributes"]["last_analysis_stats"]["malicious"]))


class Api:
    urls = {"url": "https://www.virustotal.com/api/v3/urls", \
            "domain":"https://www.virustotal.com/api/v3/domains",\
            "file": "https://www.virustotal.com/api/v3/files",\
            "ip":"https://www.virustotal.com/api/v3/ip_addresses",\
            "hash": "https://www.virustotal.com/api/v3/files"\
                }
    api_key = get_api_key().strip()

    def __init__(self, ioc_hash):
        self.ioc_hash = ioc_hash
        api_key = get_api_key()

    #GET FUNCTION
    def get(self, ioc):
        if ioc.type in ("ip", "domain"):
            vt_url = self.urls[ioc.type] + f"/{ioc.value}"
        elif ioc.type == "url" and ioc.id != "":
            vt_url = self.urls[ioc.type] + f"/{ioc.id}"
        else:
            vt_url = self.urls[ioc.type] + f"/{ioc.hash}"

        headers = {
            "accept": "application/json",
            "x-apikey": str(self.api_key)
        }

        try:
            response = requests.get(vt_url, headers=headers)
        except:
                print("[!]connection unavailable")
                exit(777)
        ioc.mal_score = response.json()['data']['attributes']['last_analysis_stats']['malicious']
        return response 

    #POST FUNCTION
    def post(self, ioc):
        vt_url = self.urls[ioc.type]

        if ioc.type == "file":
            files = {"file": (ioc.value, open(ioc.value, "rb"))}
            headers = {
                "accept": "application/json",
                "x-apikey": self.api_key
            }
            try:
                response = requests.post(vt_url, files=files, headers=headers)
            except:
                print("[!]connection unavailable")
                exit(777)

        elif ioc.type == "url":
            headers = {
                "accept": "application/json",
                "x-apikey": self.api_key,
                "content-type": "application/x-www-form-urlencoded"
            }
            payload = f"url={quote_plus(ioc.value)}"
            try:
                response = requests.post(vt_url, data=payload, headers=headers)
                ioc.id = response.json()['data']['id'].split("-")[1]
            except:
                print("[!]connection unavailable")
                exit()
        return response 


for i in range(len(sys.argv)):
    #checking if the input is valid
    if len(sys.argv) == 1 or sys.argv[i] == "-h" or sys.argv[i] == "--help":
        print("This program exit code is the atual malicious value of the analyzed IoC, this is a temporary solution")
        print("-f/--file: insert the file to analyze and/or upload (if private mode is enabled the file will not be uploaded)")
        print("-ha/--hash: file hash check")
        print("-u/--url: insert the url to analyze (if private mode is enabled the url will not be uploaded)")
        print("-d/--domain: insert the domain to analyze")
        print("-i/--ip: insert the ip to be analyze")
        print("-a/--api-file: insert the file to use to get the api, if you do so be sure to insert the key in the following format -> virus_total:api-key")
        print("-p/--priv: enable private mode to avoid upload of any data in order to mantain privacy")
        exit()
    else:
        opt = sys.argv[i]
        try:
            arg = sys.argv[i+1]
        except:
            pass

    #private mode, no upload to VT
    priv = False
    if opt == "-p" or opt == "--priv":
        priv = True

    #input file
    elif opt == "-f" or opt == "--file":
        ioc = Ioc('file', arg)

    elif opt == "-ha" or opt == "--hash":
        ioc = Ioc('hash', arg)

    #input ip
    elif opt == "-i" or opt == "--ip":
        ioc = Ioc('ip', arg)

    #input url
    elif opt == "-u" or opt == "--url":
        ioc = Ioc('url', arg)

    #input domain
    elif opt == "-d" or opt == "--domain":
        ioc = Ioc('domain', arg)


if __name__ == "__main__":
    api = Api(ioc.hash)

    if ioc.type == "file":
        response = api.get(ioc)
        if not priv:
            post_res = api.post(ioc)
            while (response.status_code != 200):
                if post_res.status_code != 200 and input('[!]error while sending the file, try again? [Y/N]') in ('yes', 'y', 'Yes', 'YES', 'Y'):
                    post_res = api.post(ioc)
                sys.stdout.write("\rWaiting for analysis to be completed..")
                sys.stdout.flush()
                response = api.get(ioc)
                time.sleep(30)
            
    elif ioc.type == "url":
        response = api.get(ioc)
        if not priv or (input(f'do you want to send the url "{ioc.value}" to VT to be analyzed? [Y/yes or N/no]') in ('yes', 'y', 'Yes', 'YES', 'Y')):
            post_res = api.post(ioc)
            while (response.status_code != 200):
                if post_res.status_code != 200 and input('[!]error while sending the url, try again? [Y/N]') in ('yes', 'y', 'Yes', 'YES', 'Y'):
                    post_res = api.post(ioc)
                sys.stdout.write("\rWaiting for analysis to be completed..")
                sys.stdout.flush()
                response = api.get(ioc)
                time.sleep(30)
    else:
        response = api.get(ioc)

    if response.status_code == 429:
        print("no more api connection can be made.. sorry")
    elif response.status_code == 200:
        ioc.preatty_print(response.json(), ioc)
    else:
        print(json.dumps(response.json(), indent=4))

exit(ioc.mal_score)