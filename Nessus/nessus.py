#!/usr/bin/env python
__author__ = "Lucas Kauffman"
__copyright__ = "Lucas Kauffman"
__email__ = "lucas@cloud101.eu"
__license__ = "Creative Commons by-nc-sa 3.0 http://creativecommons.org/licenses/by-nc-sa/3.0/" 

import requests,re,time,sys
from xml.etree.ElementTree import XML, fromstring

"""
Required non-standard Modules: 
	- Requests http://www.python-requests.org/en/latest/

Below you should fill in your username, password, and url including https and port number and 
trailing slash e.g. https://example.org:8834/
"""

username = ""
password = ""
nessus_url = ""

#You do not need to change the token value, it is automatically generated
token = ""

def initSessionID():
	global nessus_url,username,password,token
	payload = {'login':username,'password':password}
	response = requests.post(nessus_url+'login',data=payload,verify=False)
	token =  getTokenFromXML(response.text)


def getTokenFromXML(responseXML):
	root = fromstring(responseXML)
	contents = root.findall( './/contents')
	token = contents[0].find('token').text
	return token
		

def getReportTupleListFromXML(responseXML):
	root = fromstring(responseXML)
	report_elements = root.findall('.//report')
	reportList = list()
	for report in report_elements:
		report_name = report.find('readableName').text
		report_id =  report.find('name').text	
		reportList.append((report_name,report_id),)
	return reportList

def listReports():
	global nessus_url,token
	cookies = {'token':token}
	response = requests.get(nessus_url+'report/list',verify=False,cookies=cookies)
	return getReportTupleListFromXML(response.text)

def getReport(reportToken,docFormat):
        global nessus_url,token
	payload = {'chapters':'vuln_hosts_summary;vuln_by_hosts;remediations','format':'nchapter.'+docFormat,'report':reportToken[1],'token':token}
	response = requests.post(nessus_url+'report/format/generate',data=payload,verify=False)	
	fileToken = extractTokenFromXML(response.text)
	response = downloadFile(fileToken)
	writeToFile(reportToken[0]+'.'+docFormat,response.content,'wb')

def getCSV(reportToken):
        global nessus_url,token
	payload = {'format':'xslt.csv.xsl','report':reportToken[1],'token':token}
	response = requests.post(nessus_url+'report/format/generate',data=payload,verify=False)
	fileToken = extractTokenFromXML(response.text)
	response =  downloadFile(fileToken)
	writeToFile(reportToken[0]+'.csv',response.content,'wb')

def writeToFile(fileName,content,mode):
	print "[*] Writing to file "+fileName
	with  open(fileName,mode) as FILE:
		FILE.write(content)

def checkStatus(fileToken):
	global nessus_url,token
	payload = {'file':fileToken,'token':token}
	response = requests.post(nessus_url+'report/format/status',data=payload,verify=False)
	root = fromstring(response.text).find('contents')
	status = root.find('status')
	if status.text == "ready":
		return True
	

def extractTokenFromXML(responseXML):
	root = fromstring(responseXML)
	fileToken = root.findall('.//file')
	return fileToken[0].text

def downloadFile(fileToken):	
	payload = {'file':fileToken,'token':token}
	while not checkStatus(fileToken):
		print '[*] Waiting...'
		time.sleep(5)
        response = requests.post(nessus_url+'report/format/download',data=payload,verify=False)
	return response

def extractFileNameFromHTML(htmlString):
	writeToFile(fileName,response.content,'wb')
	re_file = re.findall('fileName=(.*)\">',htmlString)
	for rem in re_file:
		return rem

def printReports(reportList):
	seq = 0 
	for tup in reportList:
		print '['+str(seq)+'] ' +tup[0]+': '+tup[1]
		seq = seq + 1

def getUserInput():
	reportList = listReports()
	print "\n\n"
	print "+---------------------+"
	print "|Nessus File Retriever|"
	print "+---------------------+"
	print "\n\n"
	printReports(reportList)
	print '\n\n[*] What report do you desire to download? (press q to quit)'
	reportNumber = raw_input()
	if reportNumber.lower() == 'q':
		print "and on that bombshell..."
		sys.exit()
	try:
		reportNumber = int(reportNumber)
	except:

		print '[*] Sorry, but you did not enter an integer.'
		getUserInput()
	if reportNumber > len(reportList) - 1 or reportNumber < 0:
		print '[*] Sorry this is not possible.'
		getUserInput()
	else:
		getDocuments(reportList,reportNumber)

def getDocuments(reportList,reportNumber):
	print '[*] pdf html csv or all?'
	docFormat = raw_input()
	if docFormat == 'pdf' or docFormat == 'html':
		getReport(reportList[reportNumber],docFormat)
	elif docFormat == 'csv':
		getCSV(reportList[reportNumber])
	elif docFormat == 'all':
		print "[*] Getting the pdf report."
		getReport(reportList[reportNumber],'pdf')
		print "[*] Getting the html report."
		getReport(reportList[reportNumber],'html')
		print "[*] Getting the CSV report."
		getCSV(reportList[reportNumber])
	else:
		print "[*] It seems you made a choice which is not available, please try again."
		getDocuments()
	getUserInput()

initSessionID()
getUserInput()
