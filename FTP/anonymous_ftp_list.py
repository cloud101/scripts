#!/usr/bin/env python
__author__ = "Lucas Kauffman"
__copyright__ = "Lucas Kauffman"
__email__ = "lucas@cloud101.eu"
__license__ = "Creative Commons by-nc-sa 3.0 http://creativecommons.org/licenses/by-nc-sa/3.0/" 


import ftplib,argparse

parser = argparse.ArgumentParser()
in_group = parser.add_mutually_exclusive_group(required=True)
in_group.add_argument("-f", help="file containing ip addresses or hosts",dest="file")
in_group.add_argument("-a",help="ip address of the host",dest="address")
parser.add_argument("-d",help="delimeter to use", dest="delimeter")
out_group = parser.add_mutually_exclusive_group()
out_group.add_argument("-ox",help="xml output file",dest="xml")
out_group.add_argument("-oc",help="csv output file",dest="csv")
results = parser.parse_args()


def listFTP(ip_address):
	try:
		print "Logging into "+ip_address
		ftp = ftplib.FTP(ip_address)
		ftp.login()
		print "Logged in...listing"
		file_listing =  ftp.nlst()
		if len (file_listing) > 0:
			print "Adding to list..."
			return file_listing
		else:
			print "Nothing to list"
			return None
	except:
		print "Seems something went wrong for host "+ ip_address
	print "\n\n\n"

def getFile():
	global results
	FILE = open(results.file, 'r')
	return FILE

def createXMLFile(fileName,IPDirTupleList):
	FILE = open(fileName,'w+')
	FILE.write('<xml>\n')
        for addressTuple in IPDirTupleList:
		FILE.write('\t<host address="'+addressTuple[0].strip()+'">\n')
                if addressTuple[1] != None:
                        for line in addressTuple[1]:
                                FILE.write('\t\t<file>'+line.strip()+'</file>\n')
		FILE.write('\t</host>\n')
	FILE.write('</xml>')

def createCSVFile(fileName,IPDirTupleList):
	FILE = open(fileName,'w+')
	global results
	delimeter = results.delimeter
	if  delimeter == None  :
		delimeter = ','

	for addressTuple in IPDirTupleList:
		if addressTuple[1] != None:
			for line in addressTuple[1]:
				FILE.write(addressTuple[0].strip()+delimeter+line.strip()+'\n')
	FILE.close()


def listDirectoriesAndFiles():
	FILE = getFile()
	IPDirTupleList = list()
	for line in FILE:
		address = line.strip()
		IPDirTupleList.append((address,listFTP(line)),)
	return IPDirTupleList

def main():
	global results
	if results.xml:
		createXMLFile(results.xml, listDirectoriesAndFiles())
	elif results.csv:
		createCSVFile(results.csv, listDirectoriesAndFiles())
	else:
		print listDirectoriesAndFiles()

if __name__ == '__main__':main()


