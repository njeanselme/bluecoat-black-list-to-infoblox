import logging
import csv
import re
import sys

StructuredIOCs=[]
IOCs=[]
row={}
line_num=0
rpz_name=""
view="default"

with open(sys.argv[1], encoding='utf-8-sig') as dirtycsvfile:  # Get Data from CSV

	reader=dirtycsvfile.readlines()
	for row in reader:
		line_num = line_num + 1
	
		if not row == "":
			if re.match('define category ', row):
				rpz_name=re.sub('define category ','',row).lower().strip()
				
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
				#fqdn validation - https://www.regextester.com/103452
				#punycode validation - https://stackoverflow.com/questions/10306690/what-is-a-regular-expression-which-will-match-a-valid-domain-name-without-a-subd
				elif re.match(r"^(?=^.{4,253}$)(^((?!-)(xn--)?[a-zA-Z0-9-_]{0,62}[a-zA-Z0-9]\.)+(?!-)(xn--)?[a-zA-Z0-9]{1,62}[a-zA-Z]$)", IOC) or re.match(r"^\*\.[A-z0-9]+", IOC):
					IOCstruct["type"]='FQDN'
				else:
					print("Invalid line: "+IOC+", from line:"+str(line_num)+", content: "+row)

				#dedup
				if (IOCstruct["type"] == "network" or IOCstruct["type"] == "IP" or IOCstruct["type"] == "FQDN") and not IOCstruct["IOC"] in IOCs:
					StructuredIOCs.append(IOCstruct)
					IOCs.append(IOCstruct["IOC"])

				
#print(IOCs)
#print(StructuredIOCs)

fieldnames = ['header-responsepolicy', 'fqdn', 'comment','parent_zone','view']
fieldnameswr1 = {'header-responsepolicy':'header-responsepolicycnamerecord', 'fqdn':'fqdn', 'comment':'comment', 'parent_zone':'parent_zone', 'view':'view'}
fieldnameswr2 = {'header-responsepolicy':'header-responsepolicyipaddress', 'fqdn':'fqdn', 'comment':'comment', 'parent_zone':'parent_zone', 'view':'view'}

with open('rpz-local-lists.csv', 'w', encoding='utf-8-sig') as csvoutput:
	writer = csv.DictWriter(csvoutput, fieldnames=fieldnames)
	writer.writerow(fieldnameswr1)
	writer.writerow(fieldnameswr2)
	for StructuredIOC in StructuredIOCs:
	
		if StructuredIOC["type"] == "IP":
			responsepolicy= "responsepolicyipaddress"
		elif StructuredIOC["type"] == "FQDN":
			responsepolicy= "responsepolicycnamerecord"
			if re.match("^(?!\*)", StructuredIOC["IOC"]):
				row={'header-responsepolicy': responsepolicy, 
				'fqdn': "*."+StructuredIOC["IOC"] + "." + StructuredIOC["rpz_name"], 
				'comment': StructuredIOC["comment"], 
				'parent_zone':StructuredIOC["rpz_name"], 
				'view':view}
				writer.writerow(row)
			
		row={'header-responsepolicy': responsepolicy, 
		'fqdn': StructuredIOC["IOC"] + "." + StructuredIOC["rpz_name"], 
		'comment': StructuredIOC["comment"], 
		'parent_zone':StructuredIOC["rpz_name"], 
		'view':view}
		writer.writerow(row)
		
