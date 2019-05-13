import logging
import csv
import re
import sys
import os

StructuredIOCs=[]
lists=[]
api_key=''
inputfile =''

def usage():
  print ("\nThis is the usage function\n")
  print ('Usage: '+sys.argv[0]+' <bluecoat configuration file> <TIDE API key>')

def main():
	if len(sys.argv) == 3:
		try:
			global api_key
			global inputfile
			api_key = sys.argv[2]
			inputfile = sys.argv[1]
		except ValueError:
			print(ValueError)
			usage()
			sys.exit(2)
	else:
		usage()
		sys.exit(2)

	process_bluecoat()
	write_CSV()

	for file in lists:
		upload_to_TIDE(file + '-domain.csv')
		upload_to_TIDE(file + '-ip.csv')

def upload_to_TIDE(file):
	import httplib2
	import base64
	import pprint

	h = httplib2.Http()

	auth = base64.b64encode(bytes(api_key+':','utf-8')).decode("ascii")

	resp, content = h.request('https://platform.activetrust.net:8000/api/data/batches', 'POST',
                            headers={'Content-Type': 'text/csv',  'Authorization' : 'Basic ' + auth},
							body=open(file, "rb"))


	pp = pprint.PrettyPrinter(indent=4)
	print(content.decode('utf-8'))

def process_bluecoat():

	IOCs=[]
	row={}
	line_num=0
	rpz_name=""

	with open(inputfile, encoding='utf-8-sig') as dirtycsvfile:  # Get Data from CSV

		reader=dirtycsvfile.readlines()
		for row in reader:
			line_num = line_num + 1

			if not row == "":
				if re.match('define category ', row):
					rpz_name=re.sub('define category ','',row).lower().strip()
					lists.append(rpz_name)

				row = re.sub('^ *', 	'', row)
				row = re.sub('\n', 	'', row)
				row = re.sub('^;.*', 	'', row)
				row = re.sub('\'', 	'', row)
				row = re.sub('"', 	'', row)
				row = re.sub('^[\./]$', '', row)
				row = re.sub('^define .*$', '', row)
				row = re.sub('^end.*$', '', row)

				fields = re.split("[\;]", row , maxsplit=2)

				if len(fields) == 2:
					comment = fields[1].strip()

				IOC=fields[0].lower().strip() # to lowercase

				if not IOC == "" and not rpz_name == "":

					#fixing
					if re.match(r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",IOC):
						IOC= re.sub('\ ', '.', IOC)
					IOC = re.sub('\.$', '', IOC)
					IOC = re.sub('^\.', '*.', IOC)
					IOC = re.sub('\$$', '', IOC)
					IOC = re.sub('\?$', '', IOC)
					IOC = re.sub('–', '-', IOC)
					IOC = re.sub(r'^([A-z0-9]+)$', r'*.\1', IOC)

					IOCstruct={}
					IOCstruct["IOC"]=IOC
					IOCstruct["rpz_name"]=rpz_name
					IOCstruct["comment"]=comment
					IOCstruct["type"]=''

					#validating
					if re.match(r"^\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/\d+$",IOC):
						IOCstruct["type"]='network'
					elif re.match(r"^\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$", IOC):
						IOCstruct["type"]='IP'
					elif re.search("/", IOC):
						IOCstruct["type"]='URL'
						print("URL: " + IOC)
					elif re.match(r"^(?=^.{4,253}$)(^((?!-)(xn--)?[a-zA-Z0-9-_]{0,62}[a-zA-Z0-9]\.)+(?!-)(xn--)?[a-zA-Z0-9]{1,62}[a-zA-Z]$)", IOC) or re.match(r"^\*\.[A-z0-9]+", IOC):
						IOCstruct["type"]='FQDN'
					else:
						print("Invalid line: "+IOC+", from line:"+str(line_num)+", content: "+row)

					#dedup
					if (IOCstruct["type"] == "network" or IOCstruct["type"] == "IP" or IOCstruct["type"] == "FQDN") and not IOCstruct["IOC"] in IOCs:
						StructuredIOCs.append(IOCstruct)
						IOCs.append(IOCstruct["IOC"])
	print(lists)


def write_CSV():

	filehandlerdomain={}
	filehandlerip={}
	filewriterdomain={}
	filewriterip={}
	domainfieldnames = ['record_type', 'host', 'profile','detected','property']
	domainfieldnameswr1 = {'record_type':'record_type', 'host':'host', 'profile':'profile', 'detected':'detected', 'property':'property'}
	ipfieldnames = ['record_type', 'ip', 'profile','detected','property']
	ipfieldnameswr1 = {'record_type':'record_type', 'ip':'ip', 'profile':'profile', 'detected':'detected', 'property':'property'}

	for file in lists:
		filehandlerdomain[file] = open(file + '-domain.csv', 'w', encoding='utf-8')
		filewriterdomain[file] = csv.DictWriter(filehandlerdomain[file], quotechar='"', quoting=csv.QUOTE_NONNUMERIC, fieldnames=domainfieldnames)
		filewriterdomain[file].writerow(domainfieldnameswr1)

		filehandlerip[file] = open(file + '-ip.csv', 'w', encoding='utf-8')
		filewriterip[file] = csv.DictWriter(filehandlerip[file], quotechar='"', quoting=csv.QUOTE_NONNUMERIC, fieldnames=ipfieldnames)
		filewriterip[file].writerow(ipfieldnameswr1)

	for StructuredIOC in StructuredIOCs:
		property=""
		if re.match(r"whitelist",StructuredIOC["rpz_name"]):
			property= "Whitelist_Generic"
		else:
			property= "UncategorizedThreat_Generic"

		if StructuredIOC["type"] == "IP":
			row={'record_type':'ip',
				'ip': StructuredIOC["IOC"],
				'profile': StructuredIOC["rpz_name"],
				'detected':'',
				'property': property
				}
			filewriterip[StructuredIOC["rpz_name"]].writerow(row)
		elif StructuredIOC["type"] == "FQDN":
			row={'record_type':'host',
				'host': StructuredIOC["IOC"],
				'profile': StructuredIOC["rpz_name"],
				'detected':'',
				'property': property
				}
			filewriterdomain[StructuredIOC["rpz_name"]].writerow(row)

	for file in lists:
		filehandlerdomain[file].close()
		filehandlerip[file].close()

main()
