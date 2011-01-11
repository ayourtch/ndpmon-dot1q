#!/usr/bin/python

# takes in input the alerts via the pipe
# write the alerts in a file in XML format
# translated in HTML with XSL for display in the WEB interface

import os, time, math, tempfile, sys
from Ft.Xml.Domlette import implementation, NonvalidatingReader, PrettyPrint, Print
from Ft.Xml.XPath import Evaluate
from Ft.Xml import EMPTY_NAMESPACE
from xml.dom import Node

# The file in which we will write the alerts 
alerts = "/var/local/ndpmon/alerts.xml"

# The alert itself piped from NDPmon to this script
lines = sys.stdin.readlines()

doc = NonvalidatingReader.parseUri('file:%s' % alerts)

# The fields to complete
reason = ""
mac = ""
vendor = ""
ipv6 = ""

for line in lines:
	# Separate the fields of each line
	tmp = line.strip().split(': ')

	# Initialize the fields
	if tmp[0] == "Reason":
		reason = tmp[1].strip()
	elif tmp[0] == "MAC":
		mac = tmp[1].strip()
	elif tmp[0] == "Vendor":
		vendor = tmp[1].strip()
	elif tmp[0] == "IPv6":
		ipv6 = tmp[1].strip()

now = time.time()
str_time = time.ctime(now)

# Create the XML Element describong the alert
root = doc.documentElement

# Write the alert informations
alertNode = doc.createElementNS(None,"alert")

timeNode = doc.createElementNS(None,"time")
txtNode = doc.createTextNode(str_time)
timeNode.appendChild(txtNode)
alertNode.appendChild(timeNode)

timeSecNode = doc.createElementNS(None,"time_sec")
txtNode = doc.createTextNode(str(now))
timeSecNode.appendChild(txtNode)
alertNode.appendChild(timeSecNode)

reasonNode = doc.createElementNS(None,"reason")
txtNode = doc.createTextNode(reason)
reasonNode.appendChild(txtNode)
alertNode.appendChild(reasonNode)

macNode = doc.createElementNS(None,"mac")
txtNode = doc.createTextNode(mac)
macNode.appendChild(txtNode)
alertNode.appendChild(macNode)

if vendor != "":
	vendorNode = doc.createElementNS(None,"vendor")
	txtNode = doc.createTextNode(vendor)
	vendorNode.appendChild(txtNode)
	alertNode.appendChild(vendorNode)

ipv6Node = doc.createElementNS(None,"ipv6")
txtNode = doc.createTextNode(ipv6)
ipv6Node.appendChild(txtNode)
alertNode.appendChild(ipv6Node)

root.appendChild(alertNode)

outFile = open(alerts, 'w')
outFile.write("""<?xml version=\"1.0\"?>\n<?xml-stylesheet type=\"text/xsl\" href=\"alerts.xsl\"?>\n""")
PrettyPrint(root, outFile)
outFile.close()
