#!/usr/bin/python

import sys, os

PKG=os.popen("opkg list-installed | grep \"python-requests\" | wc -l")
if PKG == 0 :
  print "Updating opkg repository..."
  os.system("opkg update > /dev/null")
  print "Installing packages for python"
  os.system("opkg install python-requests > /dev/null")
else :
  print "Required packages are already installed..."


import requests, json

HELP="Usage: python "+sys.argv[0]+" -h|id \n\
\t -h - optional - prints this help message\n\
\t id - id of adapter"

serverAddress = "http://ant-2.fit.vutbr.cz:1338"

# return MAC address of eth0
def getMAC() :
  MAC=os.popen("ifconfig -a | grep \"eth[0-9]*\" | grep -o \"HWaddr [0-9A-F:]*\" | grep -o \"[0-9A-F:]*\"").read()
  MAC = MAC.replace('\n', '')

  return MAC

# return security ID of CPU
def getSID() :
  SID_1=os.popen("devmem2 0x01c23800 | grep \"Read*\" | grep -o \":.*\" | grep -o \"0x[0-9A-Fa-f]*\"").read()
  SID_2=os.popen("devmem2 0x01c23804 | grep \"Read*\" | grep -o \":.*\" | grep -o \"0x[0-9A-Fa-f]*\"").read()
  SID_3=os.popen("devmem2 0x01c23808 | grep \"Read*\" | grep -o \":.*\" | grep -o \"0x[0-9A-Fa-f]*\"").read()
  SID_4=os.popen("devmem2 0x01c2380c | grep \"Read*\" | grep -o \":.*\" | grep -o \"0x[0-9A-Fa-f]*\"").read()

  SID_1 = SID_1.replace('\n', '')
  SID_2 = SID_2.replace('\n', '')
  SID_3 = SID_3.replace('\n', '')
  SID_4 = SID_4.replace('\n', '')
  SID=SID_1[2:] + SID_2[2:] + SID_3[2:] + SID_4[2:]

  return SID


# Gets adapter id from specified server
#def getAdapterId():
#  response = requests.get(serverAddress + "/adapters/generateId")
#  data = response.json()
#
#  return data.get("id")


# saves adapter specified by id, mac and secure_id
def saveAdapter(mac, sid):
  headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
  data = {
    #"adapter_id": id,
    "secure_id": sid,
    "lan_mac": mac
  }

  res = requests.post(serverAddress + "/api/adapter/create", data = json.dumps(data), headers = headers)

  return res.json().adapter_id # return adapter id given by server

if __name__ == '__main__':
  if len(sys.argv) > 1 and sys.argv[1] == "-h"  :
    print HELP
    sys.exit(0)

  #ID = getAdapterId()
  #ID = '1005612700110100'
  MAC = getMAC()
  SID = getSID()
  ID = saveAdapter(MAC, SID)

  print "\tID adapteru je:", ID
  print "\tMAC adresa je: ", MAC
  print "\tSID cislo je:  ", SID

  EEPROM_DATA_VERIFICATION = "ad"
  EEPROM_DATA_VERSION = "01"

  EEPROM_DATA = EEPROM_DATA_VERIFICATION + EEPROM_DATA_VERSION

  coded_adapter_id = "{0:#0{1}x}".format(int(ID),16)[2:]

  length_adapter_id = len(coded_adapter_id)/2
  if ((len(coded_adapter_id)%2)  == 1) :
    length_adapter_id += 1

  EEPROM_DATA += "01" + str(format(length_adapter_id, '02x')) + coded_adapter_id
  EEPROM_DATA += "020100fe"

  #print "EEPROM data: ",  EEPROM_DATA, "(ID ADA HEX 0x" + coded_adapter_id + ")"
  eeprom = open("/sys/devices/soc@01c00000/1c2b000.i2c/i2c-1/1-0050/eeprom", 'w')

  hex_data = EEPROM_DATA.decode("hex")
  #print "\tEEPROM_DATA_VERIFICATION: ", EEPROM_DATA_VERIFICATION
  #print "\tEEPROM_DATA_VERSION     : ", EEPROM_DATA_VERSION
  #print "\tEEPROM_DATA - ADAPTER_ID: ", (ID + " (0x" + coded_adapter_id + ")")
  #print "\tEEPROM_DATA TOGETHER    : ", EEPROM_DATA
  print "Zapisuji AdapterID + dalsi atributy do EEPROM pameti:"
  print "\tEEPROM data: ",  EEPROM_DATA
  eeprom.write(hex_data)
  eeprom.close()

  print "Hotovo, finish!"
