import sys
import getopt
import xml.etree.ElementTree as ET

def usage():
	print (" ")
	print ("#################################################################")
	print ("#                                                               #")
	print ("#       ____   ____ .____________                  ___________  #")
	print ("#    ___\   \ /   /_| _/   _____/ ____ _____ ______\_   _____/  #")
	print ("#   /    \   Y   / __ |\_____  \ /     \__   \_  __ \    __)    #")
	print ("#  |   |  \     / /_/ |/        \   |  \/ __ \|  | \/     \     #")
	print ("#  |___|  /\___/\____ /_______  /___|  (____  /__|  \___  /     #")
	print ("#       \/           \/       \/     \/     \/          \/      #")
	print ("#                                                               #")
	print ("#################################################################")
	print (" ")
	print ("  nVdSnarF - brushes by you....")
	print (" ")
	print ("  Author: www.github.com/Pau00")
	print ("  ")
	print ("  Usage: python3 nVdSnarF.py")
	print ("  This loads a hardcoded version of the NVD database.")
	print ("  Tested with latest nvdce-modified.xml (included)")
	print ("  Examples:   ")
	print ("  python3 nVdSnarF.py -v apache -p mesos")
	print ("  python3 nVdSnarF.py -v schneider-electric")
	print (" ")
	sys.exit(0)


def search0(root,vendor):
		for entry in root.findall(".//*[@type='CVE']"):
			for desc in entry.findall(".//*[@source='cve']"):
				pass
			for vend in entry.findall(".//*[@vendor='"+vendor+"']"):
				print("----------------------------------------------------------------------------")
				print(entry.attrib)
				print(desc.text)
				print(vend.attrib)
				for ver in vend.findall(".//*[@num]"):
					print(ver.attrib)

def search1(root,vendor,product):
		for entry in root.findall(".//*[@type='CVE']"):
			for desc in entry.findall(".//*[@source='cve']"):
				pass
			for vend in entry.findall(".//*[@vendor='"+vendor+"']"):
				for prod in entry.findall(".//*[@name='"+product+"']"):
					print("----------------------------------------------------------------------------")
					print(entry.attrib)
					print(desc.text)
					print(prod.attrib)
					for ver in prod.findall(".//*[@num]"):
						print(ver.attrib)

def search2(root,product,version):
		for entry in root.findall(".//*[@type='CVE']"):
			for desc in entry.findall(".//*[@source='cve']"):
				pass
			for prod in entry.findall(".//*[@name='"+product+"']"):
				for ver in prod.findall(".//*[@num='"+version+"']"):
					print("----------------------------------------------------------------------------")
					print(entry.attrib)
					print(desc.text)
					print(prod.attrib)
					print(ver.attrib)

def search3(root,vendor,product,version):
		for entry in root.findall(".//*[@type='CVE']"):
			for desc in entry.findall(".//*[@source='cve']"):
				pass
			for vend in entry.findall(".//*[@vendor='"+vendor+"']"):
				for prod in entry.findall(".//*[@name='"+product+"']"):
					for ver in prod.findall(".//*[@num='"+version+"']"):
						print("----------------------------------------------------------------------------")
						print(entry.attrib)
						print(desc.text)
						print(prod.attrib)
						print(ver.attrib)

# Main Program
def main():
	vendor = ""
	product = ""
	version = ""

	if not len(sys.argv[1:]):
		usage()

	try:
		opts, args = getopt.getopt(sys.argv[1:], "h:v:p:n:",["help", "Vendor", "Product", "Version"])
	except getopt.GetoptError as err:
		print(err)
		usage()

	for o,a in opts:
		if o in ("-h", "--help"):
			usage()
		elif o in ("-v", "--vendor"):
			vendor = a
		elif o in ("-p", "--product"):
			product = a
		elif o in ("-n", "--version"):
			version = a
		else:
			usage()

	tree = ET.parse("nvdcve-2018.xml")
	root = tree.getroot()

	if (vendor and product and version) != "":
		search3(root,vendor,product,version)
	elif(product and version) and not(vendor) !="":
		search2(root,product,version)
	elif(vendor and product) and not(version) !="":
		search1(root,vendor,product)
	elif(vendor) and not(product and version) !="":
		search0(root,vendor)
	else:
		usage()

	print("----------------------------------------------------------------------------")

main()
