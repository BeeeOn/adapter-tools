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
import requests
import struct
import subprocess
import sys

#: BeeeOn server that should manage this gateway
SERVER_ADDRESS = "http://ant-2.fit.vutbr.cz:1338"
 
#: Path to Fitprotocold configuration file
FITPROTOD_CONF = "/etc/beeeon/fitprotocold.ini"

#: Path to devices table for Fitprotocold
DEVICE_TBL_PATH = "/var/lib/beeeon/fitprotocold.devices"

#: Path to recovery device that should be mounted
RECOVERY_FS = "/dev/mmcblk0p3"

#: Path to mounted recovery device
RECOVERY_PATH = "/mnt"

#: Path where private key should be stored
KEY_PATH = "/etc/openvpn/client.key"

#: Path where the signed certificate should be stored
CERT_PATH = "/etc/openvpn/client.crt"

#: X.509 certificate subject
CERT_SUBJECT = "/C=CZ/ST=Czech Republic/L=Brno/O=IoT/emailAddress=ca@iot.example.com"

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

def genFitprotodConf(pan_id, device_tbl_path):
	"""
	Generates fitprotocold configuration.

	:param pan_id: PAN ID of this adapter.
	:param device_table_path: Path to file with devices table.

	:return: Fitprotocold configuration
	:rtype: String
	"""

	edids =  "edid0=0x" + str(pan_id[0]) + "\n"
	edids += "edid1=0x" + str(pan_id[1]) + "\n"
	edids += "edid2=0x" + str(pan_id[2]) + "\n"
	edids += "edid3=0x" + str(pan_id[3]) + "\n"

	conf =  "[net_config]\n"
	conf += "channel=28\n"
	conf += edids
	conf += "device_table_path=" + device_tbl_path + "\n"

	logging.debug("Fitprotocold config:\n" + conf)

	return conf

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

def genKeys():
	"""
	Generates cryptography keys.

	:return: String with generated keys encoded as PEM.
	:rtype: String

	:raises RuntimeError: when error occures while generating keys

	todo:: Consult feasibility of rewriting with PyOpenSSL library.
	"""

	command = [ "openssl", "genpkey",
	            "-algorithm", "RSA",
	            "-pkeyopt", "rsa_keygen_bits:2048"]

	logging.debug('Generating crypto keys with "' + ' '.join(command) + '"')

	proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, stderr = proc.communicate()

	if proc.returncode != 0:
		raise RuntimeError(stderr)

	return stdout

def genCSR(pkey_path, gw_id):
	"""
	Generates certificate signing request from private key.

	:param pkey_path: path to private key
	:param gw_id: ID of this gateway.

	:return: PEM encoded certificate signing request.
	:rtype: String
	
	:raises RuntimeError: when error occures while generating CSR

	todo:: Consult feasibility of rewriting with PyOpenSSL library.
	"""

	command = [ "openssl", "req",
	            "-new", "-utf8",
	            "-key", pkey_path,
	            "-subj", CERT_SUBJECT+"/CN=AID="+gw_id+";/" ]

	logging.debug('Generating CSR with "' + ' '.join(command) + '"')
	
	proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, stderr = proc.communicate()

	if proc.returncode != 0:
		raise RuntimeError(stderr)

	return stdout

def signCSR(address, gw_id, csr):
	"""
	Sends :csr to server at :address to sign it and returns signed certificate.

	:param address: Address of BeeeOn server to which this gateway should register in format "http[s]://hostname[:port]".
	:param csr: PEM encoded CSR.

	:return: PEM encoded certificate.
	:rtype: String
	
	:raises requests.exceptions.RequestException: if sign request failed
	"""
	logging.debug("Sending sign request to server " + address + ".")

	headers = {"Content-type": "application/json", "Accept": "application/json"}
	data = {'id': gw_id, 'csr': csr}

	res = requests.post(address + "/api/gateway/cert/create", data = json.dumps(data), headers = headers)
	logging.debug("Server response: " + str(res))

	res.raise_for_status() # raise requests.exceptions.HTTPError if 4xx or 5xx status code

	try:
		cert = res.json()['cert']
	except ValueError:
		raise requests.exceptions.RequestException("Server replied: " + str(res.status_code) + ": " + res.text())

	return cert

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

	bckp = False
	try:
		subprocess.check_output(["mount", RECOVERY_FS, RECOVERY_PATH], stderr=subprocess.STDOUT)
		bckp = True
	except subprocess.CalledProcessError as e:
		err = True
		logging.error("Could not mount recovery partition, initialization will NOT be backed up!\nError: " + str(e))

	fitprotod_conf = genFitprotodConf(pan_id, DEVICE_TBL_PATH)
	try:
		with open(FITPROTOD_CONF, 'w') as fitprotod_conf_file:
			fitprotod_conf_file.write(fitprotod_conf)
	except IOError as e:
		logging.critical("Could not save fitprotocold configuration. " + str(e))
		sys.exit(1)
	if bckp:
		try:
			with open(RECOVERY_PATH+FITPROTOD_CONF, 'w') as fitprotod_conf_bckp:
				fitprotod_conf_bckp.write(fitprotod_conf)
		except IOError as e:
			err = True
			logging.error("Could not backup fitprotocold configuration. " + str(e))

	try:
		storeToEEPROM(gw_id)
		print("Gateway ID stored to EEPROM.")
	except IOError as e:
		err = True
		logging.error("Storing gateway ID to EEPROM failed with: " + str(e))

	try:
		keys = genKeys()
		with open(KEY_PATH, 'w') as keyfile:
			keyfile.write(keys)
		print("2048b RSA keys generated.")
	except RuntimeError as e:
		logging.critical("Key generation failed with: " + str(e))
		sys.exit(1)
	except IOError as e:
		logging.critical("Could not save private key: " + str(e))
		sys.exit(1)
	if bckp:
		try:
			with open(RECOVERY_PATH+KEY_PATH, 'w') as keyfile_bckp:
				keyfile_bckp.write(keys)
		except IOError as e:
			err = True
			logging.error("Could not backup private key: " + str(e))

	try:
		csr = genCSR(KEY_PATH, gw_id)
		cert = signCSR(SERVER_ADDRESS, gw_id, csr)
		logging.debug("Received certificate:\n " + cert)
		with open(CERT_PATH, 'w') as cert_file:
			cert_file.write(cert)
		print("Certificate successfully signed and stored.")
		if bckp:
			try:
				with open(RECOVERY_PATH+CERT_PATH, 'w') as cert_bckp:
					cert_bckp.write(cert)
			except IOError as e:
				err = True
				logging.error("Could not backup certificate: " + str(e))
	except RuntimeError as e:
		logging.critical("CSR generation failed with: " + str(e))
		sys.exit(1)
	except IOError as e:
		logging.critical("Could not save certificate: " + str(e))
		sys.exit(1)

	try:
		subprocess.check_output(["systemctl", "enable", "beeeon-adaapp"], stderr=subprocess.STDOUT)
		print("AdaApp enabled")
	except CalledProcessError as e:
		err = True
		logging.error("Enabling AdaApp failed with: " + str(e))

	if bckp:
		try:
			subprocess.check_call(["umount", RECOVERY_PATH])
		except subprocess.CalledProcessError:
			err = True
			logging.error("Could not unmount "+RECOVERY_PATH+", please do it manually.")

	if err:
		print("Initialization finished with some errors.")
		sys.exit(2)
	else:
		print("Initialization finished successfully.")
		sys.exit(0)
