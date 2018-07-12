#!/usr/bin/env python3
"""
Factory initialization script for BeeeOn gateways.

This script serves for initial setting of a gateway, registering it to a
BeeeOn server and generating cryptographic keys for secure VPN connection
between a gateway and managing server.
"""

import argparse
import base64
import configparser
import json
import logging
import mmap
import os
import random
import requests
import string
import struct
import subprocess
import sys

#: BeeeOn server that should manage this gateway
SERVER_ADDRESS = "http://ant-dev.fit.vutbr.cz:1337"
 
#: Path to the configuration file
CONFIG_FILE = "/etc/beeeon/gateway/config.d/custom.ini"

#: Path to recovery device that should be mounted
RECOVERY_FS = "/dev/mmcblk0p3"

#: Path to mounted recovery device
RECOVERY_PATH = "/mnt"

#: Range setting for Fitprotocold channel
CHANNEL_MIN = 0
CHANNEL_MAX = 31

#: Path where private key should be stored
KEY_PATH = "/etc/ssl/beeeon/private/beeeon_gateway.key"

#: Path where the signed certificate should be stored
CERT_PATH = "/etc/ssl/beeeon/certs/beeeon_gateway.crt"

#: X.509 certificate subject
CERT_SUBJECT = "/C=CZ/ST=Czech Republic/L=Brno/O=BeeeOn/emailAddress=info@beeeon.org"

#: Characters that will be used for passphrase
PASSPHRASE_CHARS = string.ascii_letters + string.digits + ' '

#: Length of the passphrase
PASSPHRASE_LEN = 32

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
		for i in range(0, SID_LEN // WORD_LEN):
			sid_word = mem_sid.read(WORD_LEN)
			logging.debug("SID WORD[" + str(i) + "] = " + sid_word.hex())
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

	:return: ID of this gateway
	:rtype: Integer

	:raises requests.exceptions.RequestException: if registration request failed
	"""
	logging.debug("Sending registration request to server " + address + ".")

	headers = {"Content-type": "application/json", "Accept": "application/json"}
	data = {'mac': mac, 'secID': sid}
 
	res = requests.post(address + "/api/gateway", data = json.dumps(data), headers = headers)
	logging.debug("Server response [" + str(res.status_code) + "]: " + str(res.text))
 
	res.raise_for_status() # raise requests.exceptions.HTTPError if 4xx or 5xx status code

	dres = res.json()


	if dres['data']['mac'].upper() != mac.upper():
		raise KeyError("Returned mac address differs")
	if dres['data']['secID'].upper() != sid.upper():
		raise KeyError("Returned secure ID differs")

	return dres['data']['gwID']

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

	enc_gw_id_size = len(enc_gw_id) // 2 # 2 hex digits per byte
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
	with open(EEPROM_PATH, 'wb') as eeprom:
		eeprom.write(data.encode())

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
	            "-subj", CERT_SUBJECT+"/CN="+str(gw_id)+"/" ]

	logging.debug('Generating CSR with "' + ' '.join(command) + '"')
	
	proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, stderr = proc.communicate()

	if proc.returncode != 0:
		raise RuntimeError(stderr)

	return stdout.decode()

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

	res = requests.post(address + "/api/gateway/" + str(gw_id) + "/cert", data = json.dumps(data), headers = headers)
	logging.debug("Server response: " + str(res))

	res.raise_for_status() # raise requests.exceptions.HTTPError if 4xx or 5xx status code

	try:
		cert = res.json()['data']['cert']
	except ValueError:
		raise requests.exceptions.RequestException("Server replied: " + str(res.status_code) + ": " + res.text())

	return cert


def genPassphrase(charSet, length):
	"""
	Generates random string of characters from :charSet of the length :length.

	:param charSet: String with characters that can be used for passphrase generation.
	:param length:  Integer defining the length of the generated passphrase.
 
	:return: Random passphrase of the given length.
	:rtype:  String
	"""

	# Create a static random context if it has not been defined yet
	if not hasattr(genPassphrase, "rng"):
		genPassphrase.rng = random.SystemRandom()

	return ''.join([ genPassphrase.rng.choice(charSet) for _ in range(length) ])


if __name__ == '__main__':
	err = False

	parser = argparse.ArgumentParser("python "+sys.argv[0], description="Factory initialization script for BeeeOn gateways.")
	parser.add_argument("--debug", action='store_true', help="print debugging messages")
	args = parser.parse_args()

	config = configparser.ConfigParser()
	config.optionxform = lambda option: option # Keep the case intact

	log_lvl = logging.ERROR
	if args.debug:
		log_lvl = logging.DEBUG
	logging.basicConfig(format="%(levelname)s:\t%(message)s", level=log_lvl)

	bckp = False
	try:
		subprocess.check_output(["mount", RECOVERY_FS, RECOVERY_PATH], stderr=subprocess.STDOUT)
		bckp = True
	except subprocess.CalledProcessError as e:
		err = True
		logging.error("Could not mount recovery partition, initialization will NOT be backed up!")
		logging.error("Error (" + str(e.returncode) + "): " + e.output.decode())

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
	
	config['gateway'] = {}
	try:
		gw_id = register(SERVER_ADDRESS, mac, sid)
		config['gateway']['id'] = str(gw_id)
		print("Gateway ID:\t" + str(gw_id))
	except KeyError as e:
		logging.critical("Server returned unexpected answer during registration: " + str(e))
		sys.exit(1)
	except requests.exceptions.RequestException as e:
		try:
			for error in e.response.json()['errors']:
				logging.critical(error)
		except:
			logging.critical("Registering the gateway failed with: " + str(e))
		sys.exit(1)

	config['fitp'] = {'channel': str(random.randint(CHANNEL_MIN, CHANNEL_MAX))}

	config['credentials'] = {'crypto.passphrase': genPassphrase(PASSPHRASE_CHARS, PASSPHRASE_LEN)}

	try:
		storeToEEPROM(gw_id)
		print("Gateway ID stored to EEPROM.")
	except IOError as e:
		err = True
		logging.error("Storing gateway ID to EEPROM failed with: " + str(e))

	config['ssl'] = {}
	try:
		keys = genKeys()

		try:
			os.makedirs(os.path.dirname(KEY_PATH))
		except OSError as e:
			pass

		with open(KEY_PATH, 'wb') as keyfile:
			keyfile.write(keys)

		config['ssl']['key'] = KEY_PATH
		print("2048b RSA keys generated.")
	except RuntimeError as e:
		logging.critical("Key generation failed with: " + str(e))
		sys.exit(1)
	except IOError as e:
		logging.critical("Could not save private key: " + str(e))
		sys.exit(1)
	if bckp:
		try:
			with open(RECOVERY_PATH+KEY_PATH, 'wb') as keyfile_bckp:
				keyfile_bckp.write(keys)
		except IOError as e:
			err = True
			logging.error("Could not backup private key: " + str(e))

	try:
		csr = genCSR(KEY_PATH, gw_id)
		cert = signCSR(SERVER_ADDRESS, gw_id, csr)
		logging.debug("Received certificate:\n " + cert)

		try:
			os.makedirs(os.path.dirname(CERT_PATH))
		except OSError as e:
			pass

		with open(CERT_PATH, 'w') as cert_file:
			cert_file.write(cert)
		config['ssl']['certificate'] = CERT_PATH
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
		with open(CONFIG_FILE, 'w+') as configfile:
			config.write(configfile)
		print("Configuration successfully saved.")
	except IOError as e:
		logging.critical("Could not save the configuration. " + str(e))
		sys.exit(1)
	if bckp:
		try:
			with open(RECOVERY_PATH+CONFIG_FILE, 'w+') as configfile:
				config.write(configfile)
		except IOError as e:
			err = True
			logging.error("Could not backup the configuration. " + str(e))

	try:
		subprocess.check_output(["systemctl", "enable", "beeeon-gateway"], stderr=subprocess.STDOUT)
		print("BeeeOn Gateway enabled")
	except subprocess.CalledProcessError as e:
		err = True
		logging.error("Enabling BeeeOn Gateway failed with: " + str(e))

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
