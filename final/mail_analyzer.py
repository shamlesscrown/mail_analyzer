#!/usr/bin/python3
import email
import json
import os 
import sys
import re
import time
import datetime
import base64
import subprocess
import hashlib
from collections import ChainMap

#setting up colored output
from colorama import init, Fore, Back, Style
init()

# fai un argv che se inserito allora NON fa l'upload del file.

text = "@@@  @@@   @@@@@@   @@@        @@@@@@   @@@@@@@@@@   @@@  @@@@@@@@   @@@@@@\n"\
	   "@@@  @@@  @@@@@@@@  @@@       @@@@@@@@  @@@@@@@@@@@  @@@  @@@@@@@@  @@@@@@@@\n"\
 	   "@@!  !@@  @@!  @@@  @@!       @@!  @@@  @@! @@! @@!  @@!       @@!  @@!  @@@\n"\
	   "!@!  @!!  !@!  @!@  !@!       !@!  @!@  !@! !@! !@!  !@!      !@!   !@!  @!@\n"\
	   "@!@@!@!   @!@!@!@!  @!!       @!@!@!@!  @!! !!@ @!@  !!@     @!!    @!@!@!@!\n"\
	   "!!@!!!    !!!@!!!!  !!!       !!!@!!!!  !@!   ! !@!  !!!    !!!     !!!@!!!!\n"\
	   "!!: :!!   !!:  !!!  !!:       !!:  !!!  !!:     !!:  !!:   !!:      !!:  !!!\n"\
	   ":!:  !:!  :!:  !:!   :!:      :!:  !:!  :!:     :!:  :!:  :!:       :!:  !:!\n"\
	   " ::  :::  ::   :::   :: ::::  ::   :::  :::     ::    ::   ::       ::   :::\n"\
	   " :   :::   :   : :  : :: : :   :   : :   :      :    :    : :        :   : :\n"

print(text)

#definind list of IoC
fNames = []
ipv4s = []
ipv6s = []
urls = []
domains = []
results = [0]
ioc = []
sw = 0                                                                  

for i in range(len(sys.argv)):
	if len(sys.argv) == 1 or sys.argv[i] == "-h" or sys.argv[i] == "--help":
		print("use -f option followed by the .eml file path")
		print("-f/--file: insert the file to upload and analyze. \n    usage --> -f <fileName.eml>")
		print("-p/--priv: enable the private mode, no personal data will be upload to third party sites.\n    usage --> -p")
		exit()

	if sys.argv[i] == "-f" or sys.argv[i] == "--file":
		if not sys.argv[i+1]:
			print("insert a file to analyze")
			exit()
		filepath = sys.argv[i+1]
		if not os.path.isfile(filepath):
			print("file does not exist..")
			exit()

	#private mode, do not uplaod any file on VT
	elif sys.argv[i] == "--priv" or sys.argv[i] == "-p":
		sw = 1

	elif re.search("^-.*", sys.argv[i]):
		print(f"{sys.argv[i]} is not a valid option")
		exit()

mail = filepath

#defining vars
sections = []
text = ""
header_dict = {}
json_string = json.dumps("")
c = 0

#separate the email in sections to better read the email raw
with open(mail, "r") as f:
	text = f.readline()
	for row in f:
		if "Received" in row:
			sections.append(text.replace("Received", f"Received{c}"))
			c += 1
			text = row
		elif re.search("^Content-Type", row):
			sections.append(text)
			text = row
		else:
			text += row
	sections.append(text)

#extracting IoC from email secitons
rows = []
line = ""
fName = ""
print("analyzing email... This operation could take few minutes..\n\n")
for section in sections:
	if "filename=" in section:
		#extracting the base64 data of the file
		fName_, file = section.split("\n\n")[0], section.split("\n\n")[1]
		file = file.strip()

		#grep the file name, a bit horrible code but is ok for now
		for sec in fName_.split(";"):
			if re.search('filename=', sec):
				fName = re.search(r'filename=\".*\"', sec).group()
				fName = fName.split("=")[1].replace('"', "")

		#writing out the file
		with open(f'./extracted_files/{fName}', "wb") as f:
			f.write(base64.b64decode(str(file)))
			time.sleep(1)

		fNames.append(fName)

	#cheking for url in html section
	elif "Content-Type: text/html" in section:
		pattern = r"href=\"((http|https):\/\/).* "
		hit = re.search(pattern, section)
		if len(hit.group()) != 0:
			urls.append(hit.group()[:-2])
			domains.append(hit.group().split("/")[2])

	else:
		#checking for IPv4 addresses
		pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
		hit = re.search(pattern, section)
		if hit:
			ipv4s.append(hit.group())

		#checking for IPv6 addresses
		pattern = r"\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b"
		hit = re.search(pattern, section)
		if hit:
			ipv6s.append(hit.group())

		#checking for urls
		pattern = r"\b((http|https):\/\/).* "
		hit = re.search(pattern, section)
		if hit:
			urls.append(hit.group())
			domains.append(hit.group().split("/")[2])

		#checking for domains
		pattern = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"
		hit = re.search(pattern, section)
		if hit:
			domains.append(hit.group().strip())

#																	  #
# after the gathering od the IoC they will be load into the resources #
#																	  #

###Checking IoC with VT###

#files checking, private and public mode
for fName in fNames:
	if sw:
		result = subprocess.run(["python3", "vt_api.py", "-f", f"./extracted_files/{fName}", "-p"])
	else:
		result = subprocess.run(["python3", "modules/vt_api.py", "-f", f"./extracted_files/{fName}"])
	if int(result.returncode) == 777:
		exit()
	elif int(result.returncode) != 0:
		results.append(result.returncode)
		ioc.append(fName)

#ipv4 checking
ipv4s = list(dict.fromkeys(ipv4s))
for ip in ipv4s:
	result = subprocess.run(["python3", "modules/vt_api.py", "-i", f"{ip}"])
	if int(result.returncode) == 777:
		exit()
	elif int(result.returncode) != 0:
		results.append(result.returncode)
		ioc.append(ip)

#url checking
for url in urls:
	print(urls)
	result = subprocess.run(["python3", "modules/vt_api.py", "-u", f"{url}"])
	if int(result.returncode) == 777:
		exit()
	elif int(result.returncode) != 0:
		results.append(result.returncode)
		ioc.append(url)

#domain checking
for dom in domains:
	result = subprocess.run(["python3", "modules/vt_api.py", "-d", f"{dom}"])
	if int(result.returncode) == 777:
		exit()
	elif int(result.returncode) != 0:
		results.append(result.returncode)
		ioc.append(dom)

results = [x for x in results if x != 0]
if len(results) != 0:
	print(Back.RED + f"final malicious score: {int(sum(results) / len(results))}/100" + Style.RESET_ALL)
else:
	print(Back.GREEN + "No malicious entity has been found" + Style.RESET_ALL)

if len(ioc) != 0:
	print(f"following with the malicious IoC found:")
	for i in ioc:
		print(f"    {i}")

#PER IL FINAL SCORE IMPLEMENTA UN EXIT CODE IN 2_VT_APY.PY, 
#IL CUI VALORE È PARI AL MALICIOUS SCORE, COSI CHE PUOI RIPRENDERLO DA QUI