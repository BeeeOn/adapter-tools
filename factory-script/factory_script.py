#!/usr/bin/python

import argparse
import base64
import json
import logging
import mmap
import os
import requests
import struct
import subprocess
import sys

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

def storeToEEPROM(gw_id):
	"""
	Stores gateway ID and warranty byte to EEPROM.

	:param gw_id: ID of this gateway.
	"""
	
	EEPROM_PATH = "/sys/devices/platform/soc@01c00000/1c2b000.i2c/i2c-1/1-0050/eeprom"
	EEPROM_MAGIC_NUMBER = "ad"
	EEPROM_TABLE_VERSION = "01"
	EEPROM_TYPE_GW_ID = "01"
	EEPROM_TYPE_WARRANTY = "02"
	EEPROM_WARRANTY_LEN = "01"
	EEPROM_WARRANTY = "00"
	EEPROM_END_OF_DATA = "ff"
	
	CODED_GW_ID_MIN_LEN = 14 # Minimal length of CODED_GW_ID in hexadecimal characters

	enc_gw_id = "{0:0{1}x}".format(int(gw_id), CODED_GW_ID_MIN_LEN) # encode gw_id as hex chars

	enc_gw_id_size = len(enc_gw_id)/2 # 2 hex digits per byte
	enc_gw_id_size = enc_gw_id_size if (len(enc_gw_id)%2 == 0) else enc_gw_id_size+1 # round to bytes

	data =  EEPROM_MAGIC_NUMBER
	data += EEPROM_TABLE_VERSION

	data += EEPROM_TYPE_GW_ID
	data += format(enc_gw_id_size, '02x')
	data += enc_gw_id
	
	data += EEPROM_TYPE_WARRANTY
	data += EEPROM_WARRANTY_LEN
	data += EEPROM_WARRANTY

	data += EEPROM_END_OF_DATA
	logging.debug("EEPROM data: " + data)

	logging.info("Writing gateway ID to EEPROM.")
	with open(EEPROM_PATH, 'w') as eeprom:
		eeprom.write(data.decode("hex"))

if __name__ == '__main__':
	parser = argparse.ArgumentParser("python "+sys.argv[0], description='Initialization factory script for BeeeOn gateways.')
	parser.add_argument('--debug', action='store_true', help='print debugging messages')
	args = parser.parse_args()

	log_lvl = logging.ERROR
	if args.debug:
		log_lvl = logging.DEBUG
	logging.basicConfig(format='%(levelname)s:\t%(message)s', level=log_lvl)

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

	storeToEEPROM(ID)

	print "Povoluji spusteni AdaApp"
	os.system("systemctl enable beeeon-adaapp")

	print "Hotovo, finish!"
