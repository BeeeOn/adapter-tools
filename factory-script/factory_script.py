#!/usr/bin/python

import base64
import json
import logging
import mmap
import os
import requests
import struct
import subprocess
import sys

HELP="Usage: python "+sys.argv[0]+" -h|id \n\
\t -h - optional - prints this help message\n\
\t id - id of adapter"

serverAddress = "http://ant-2.fit.vutbr.cz:1338"

def getMAC(iface):
	"""
	Retrieves MAC address of given interface.

	:param iface: Name of the interface whose MAC address we want.

	:return: String with MAC address.
	:rtype:  String

	:raises IOError: if MAC address for given :iface cannot be retrieved
	"""
	mac = ""

	with open('/sys/class/net/'+iface+'/address') as macFile:
		mac = macFile.readline().strip()
	
	mac = mac.upper() # compatibility with old format

	return mac

def getSID():
	"""
	Retrieves security ID (SID) of CPU.

	:return: String with 16 bytes of SID coded as hexa-numbers.
	:rtype: String
	"""
	logging.debug('Getting CPU security ID...')

	SID_ADDR = 0x01c23800
	SID_LEN = 16
	WORD_LEN = 4
	MAP_MASK = mmap.PAGESIZE - 1

	with open("/dev/mem", "rb") as mem:
		mem_sid = mmap.mmap(mem.fileno(), mmap.PAGESIZE, mmap.MAP_SHARED, mmap.PROT_READ, offset=SID_ADDR & ~MAP_MASK)
		mem_sid.seek(SID_ADDR & MAP_MASK)

		sid = ""
		for i in range(0, SID_LEN / WORD_LEN):
			sid_word = mem_sid.read(WORD_LEN)
			sid_int = struct.unpack("<L", sid_word) # Because of Little-Endians
			sid += '{0:08X}'.format(sid_int[0])

		mem_sid.close()

	return sid

# saves adapter specified by id, mac and secure_id
def save_adapter(mac, sid):
	headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
	data = {
		"secure_id": sid,
		"lan_mac": mac
	}

	res = requests.post(serverAddress + "/api/adapter/create", data = json.dumps(data), headers = headers)

	return res.json() # return adapter json

if __name__ == '__main__':
	logging.basicConfig(format='%(levelname)s:\t%(message)s')
	if len(sys.argv) > 1 and sys.argv[1] == "-h":
		print HELP
		sys.exit(0)

	MAC = getMAC("eth0")
	SID = getSID()
	adapter = save_adapter(MAC, SID)

	ID = adapter["adapter_id"]
	cert = base64.b64decode(adapter["cert"])
	key = base64.b64decode(adapter["key"])
	pan_id = adapter["pan_id"]  # [3E, 29. C3, 39]
	
	cert_file_path = "/etc/openvpn/client.crt"
	key_file_path = "/etc/openvpn/client.key"
	conf_file_path = "/etc/beeeon/fitprotocold.ini"
	
	recovery_fs = "/dev/mmcblk0p3"
	recovery_mnt_path = "/mnt"
	
	subprocess.call(["mount %s %s" % (recovery_fs, recovery_mnt_path)], shell=True);
	
	for path in [cert_file_path, recovery_mnt_path+cert_file_path]:
		with open(path, "w") as cert_file:
			cert_file.write(cert)
	
	for path in [key_file_path, recovery_mnt_path+key_file_path]:
		with open(path, "w") as key_file:
			key_file.write(key)
	
	edids = "edid0=0x{0}\nedid1=0x{1}\nedid2=0x{2}\nedid3=0x{3}\n".format(pan_id[0], pan_id[1], pan_id[2], pan_id[3])
	
	for path in [conf_file_path, recovery_mnt_path+conf_file_path]:
		with open(path, "w") as conf_file:
			conf_file.write("[net_config]\nchannel=28\n"+edids+"device_table_path=/var/lib/beeeon/fitprotocold.devices\n")
	
	subprocess.call(["umount %s" % (recovery_mnt_path)], shell=True);
	
	print "\tID adapteru je:", ID
	print "\tMAC adresa je: ", MAC
	print "\tSID cislo je:  ", SID
	print "\tPAN id je:     ", pan_id

	EEPROM_DATA_VERIFICATION = "ad"
	EEPROM_DATA_VERSION = "01"

	EEPROM_DATA = EEPROM_DATA_VERIFICATION + EEPROM_DATA_VERSION

	coded_adapter_id = "{0:#0{1}x}".format(int(ID), 16)[2:]

	length_adapter_id = len(coded_adapter_id)/2
	if ((len(coded_adapter_id)%2)  == 1) :
		length_adapter_id += 1

	EEPROM_DATA += "01" + str(format(length_adapter_id, '02x')) + coded_adapter_id
	EEPROM_DATA += "020100fe"

	#print "EEPROM data: ",  EEPROM_DATA, "(ID ADA HEX 0x" + coded_adapter_id + ")"
	eeprom = open("/sys/devices/platform/soc@01c00000/1c2b000.i2c/i2c-1/1-0050/eeprom", 'w')

	hex_data = EEPROM_DATA.decode("hex")
	#print "\tEEPROM_DATA_VERIFICATION: ", EEPROM_DATA_VERIFICATION
	#print "\tEEPROM_DATA_VERSION     : ", EEPROM_DATA_VERSION
	#print "\tEEPROM_DATA - ADAPTER_ID: ", (ID + " (0x" + coded_adapter_id + ")")
	#print "\tEEPROM_DATA TOGETHER    : ", EEPROM_DATA
	print "Zapisuji AdapterID + dalsi atributy do EEPROM pameti:"
	print "\tEEPROM data: ",  EEPROM_DATA
	eeprom.write(hex_data)
	eeprom.close()

	print "Povoluji spusteni AdaApp"
	os.system("systemctl enable beeeon-adaapp")

	print "Hotovo, finish!"
