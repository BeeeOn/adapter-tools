#!/usr/bin/python
"""
Factory initialization script for BeeeOn gateways.

This script serves for initial setting of a gateway, registering it to a
BeeeOn server and generating cryptographic keys for secure VPN connection
between a gateway and managing server.

todo:: Remove all references to adapter and adapter ID (aid).
"""

from __future__ import print_function

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

#: BeeeOn server that should manage this gateway
SERVER_ADDRESS = "http://ant-2.fit.vutbr.cz:1338"

def getMAC(iface):
	"""
	Retrieves MAC address of given interface.

	:param iface: Name of the interface whose MAC address we want.

	:return: String with MAC address.
	:rtype:  String

	:raises IOError: if MAC address for given :iface cannot be retrieved
	"""
	mac = ''

	with open("/sys/class/net/"+iface+"/address") as macFile:
		mac = macFile.readline().strip()
	
	mac = mac.upper() # compatibility with old format

	return mac

def getSID():
	"""
	Retrieves security ID (SID) of CPU.

	:return: String with 16 bytes of SID coded as hexa-numbers.
	:rtype: String

	:raises IOError: if denied access to /dev/mem
	"""
	logging.debug("Getting CPU security ID...")

	SID_ADDR = 0x01c23800 #: address of secure ID in memory
	SID_LEN = 16 #: length od secure ID in bytes
	WORD_LEN = 4 #: number of bytes in one word for Endian fixing
	MAP_MASK = mmap.PAGESIZE - 1 #: mask used for solving issues with memory pages

	with open("/dev/mem", 'rb') as mem:
		mem_sid = mmap.mmap(mem.fileno(), mmap.PAGESIZE, mmap.MAP_SHARED, mmap.PROT_READ, offset=SID_ADDR & ~MAP_MASK)
		mem_sid.seek(SID_ADDR & MAP_MASK)

		sid = ''
		for i in range(0, SID_LEN / WORD_LEN):
			sid_word = mem_sid.read(WORD_LEN)
			logging.debug("SID WORD[" + str(i) + "] = " + sid_word.encode('hex'))
			sid_int = struct.unpack('<L', sid_word) # Because of Little-Endians
			sid += "{0:0{1}X}".format(sid_int[0], WORD_LEN*2) # two hex digits per byte

		mem_sid.close()

	return sid

def register(address, mac, sid):
	"""
	Register this gateway to BeeeOn server at address :address.

	:param address: Address of the BeeeOn server to which this gateway should register as "http[s]://hostname[:port]".
	:param mac: MAC address of the main interface of this gateway.
	:param sid: Secure ID of this gateway's CPU.

	:return: Tuple with ID of this gateway and PAN ID.
	:rtype: Tuple

	:raises requests.exceptions.RequestException: if registration request failed
	"""
	logging.debug("Sending registration request to server " + address + ".")

	headers = {"Content-type": "application/json", "Accept": "application/json"}
	data = {'lan_mac': mac, 'secure_id': sid}
 
	res = requests.post(address + "/api/gateway/create", data = json.dumps(data), headers = headers)
	logging.debug("Server response: " + str(res))
 
	res.raise_for_status() # raise requests.exceptions.HTTPError if 4xx or 5xx status code

	dres = res.json()
	return (dres['gw_id'], dres['pan_id'])

def storeToEEPROM(gw_id):
	"""
	Stores gateway ID and warranty byte to EEPROM.

	:param gw_id: ID of this gateway.

	:raises IOException: if opening or writing to EEPROM fails
	"""
	
	#: path to EEPROM device
	EEPROM_PATH = "/sys/devices/platform/soc@01c00000/1c2b000.i2c/i2c-1/1-0050/eeprom"
	EEPROM_MAGIC_NUMBER = 'ad'
	EEPROM_TABLE_VERSION = '01' #: version of eeprom data coding
	EEPROM_TYPE_GW_ID = '01'
	EEPROM_TYPE_WARRANTY = '02'
	EEPROM_WARRANTY_LEN = '01'
	EEPROM_WARRANTY = '00'
	EEPROM_END_OF_DATA = 'ff'
	
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
		eeprom.write(data.decode('hex'))

if __name__ == '__main__':
	err = False

	parser = argparse.ArgumentParser("python "+sys.argv[0], description="Factory initialization script for BeeeOn gateways.")
	parser.add_argument("--debug", action='store_true', help="print debugging messages")
	args = parser.parse_args()

	log_lvl = logging.ERROR
	if args.debug:
		log_lvl = logging.DEBUG
	logging.basicConfig(format="%(levelname)s:\t%(message)s", level=log_lvl)

	try:
		mac = getMAC("eth0")
	except IOError as e:
		err = True
		logging.error("Cannot determine MAC address for eth0, using 00:00:00:00:00:00.")
		mac = "00:00:00:00:00:00"
	print("MAC address:\t" + mac)
	
	try:
		sid = getSID()
		print("Secure ID:\t" + sid)
	except Exception as e: # Exception is too general, but the documentation isn't too specific either :-/
		logging.critical("Getting secure ID failed with: " + str(e))
		sys.exit(1)
	
	try:
		gw_id, pan_id = register(SERVER_ADDRESS, mac, sid)
		print("Gateway ID:\t" + gw_id)
		print("PAN ID:\t\t" + str(pan_id))
	except KeyError as e:
		logging.critical("Server returned unexpected answer during registration: " + str(e))
		sys.exit(1)
	except requests.exceptions.RequestException as e:
		logging.critical("Registering the gateway failed with: " + str(e))
		sys.exit(1)
	
	try:
		storeToEEPROM(gw_id)
		print("Gateway ID stored to EEPROM.")
	except IOError as e:
		err = True
		logging.error("Storing gateway ID to EEPROM failed with: " + str(e))

	if err:
		print("Initialization finished with some errors.")
		sys.exit(2)
	else:
		print("Initialization finished successfully.")
		sys.exit(0)
