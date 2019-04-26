import logging
import csv
import re
import sys
import os

StructuredIOCs=[]
IOCs=[]
row={}
line_num=0
lists=[]
rpz_name=""

# based on https://gist.github.com/ReedJessen/1cb97a358811f3ea154c81bbd5bd80f8
import os

def split(filehandler, delimiter=',', row_limit=10000, output_name_template='output_%s.csv', output_path='.', keep_headers=True):
    import csv
    reader = csv.reader(filehandler, delimiter=delimiter)
    current_piece = 1
    current_out_path = os.path.join(
         output_path,
         output_name_template  % current_piece
    )
    current_out_writer = csv.writer(open(current_out_path, 'w', newline=''), delimiter=delimiter)
    current_limit = row_limit
    if keep_headers:
        headers = reader.__next__()
        current_out_writer.writerow(headers)
    for i, row in enumerate(reader):
        if i + 1 > current_limit:
            current_piece += 1
            current_limit = row_limit * current_piece
            current_out_path = os.path.join(
               output_path,
               output_name_template  % current_piece
            )
            current_out_writer = csv.writer(open(current_out_path, 'w'), delimiter=delimiter)
            if keep_headers:
                current_out_writer.writerow(headers)
        current_out_writer.writerow(row)

with open(sys.argv[1], encoding='utf-8-sig') as dirtycsvfile:  # Get Data from CSV

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
				elif re.match(r"^(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-_]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)", IOC) or re.match(r"^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.(xn--)?[a-z0-9-]{2,})$", IOC) or re.match(r"^\*\.[A-z0-9]+", IOC):
					IOCstruct["type"]='FQDN'
				else:
					print("Invalid line: "+IOC+", from line:"+str(line_num)+", content: "+row)

				#dedup
				if (IOCstruct["type"] == "network" or IOCstruct["type"] == "IP" or IOCstruct["type"] == "FQDN") and not IOCstruct["IOC"] in IOCs:
					StructuredIOCs.append(IOCstruct)
					IOCs.append(IOCstruct["IOC"])
				
#print(IOCs)
#print(StructuredIOCs)
print(lists)
filehandler={}
filewriter={}
fieldnames = ['domain']
fieldnameswr1 = {'domain':'domain'}

for file in lists:
	filehandler[file] = open(file + '.csv', 'w', encoding='utf-8-sig')
	filewriter[file] = csv.DictWriter(filehandler[file], fieldnames=fieldnames)
	filewriter[file].writerow(fieldnameswr1)
	
for StructuredIOC in StructuredIOCs:		
	row={'domain': StructuredIOC["IOC"]}
	filewriter[StructuredIOC["rpz_name"]].writerow(row)

for file in filehandler:
	filehandler[file].close()
	split(open(file+ '.csv','r'),row_limit=10000, output_name_template= file + '_%s.csv', output_path='.', keep_headers=True);