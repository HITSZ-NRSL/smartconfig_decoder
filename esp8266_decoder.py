import os
import commands
import string
from subprocess import Popen, PIPE

commands.getstatus('airmon-ng stop mon0')
commands.getstatus('airmon-ng start wlan0')
#list existing Aps and find their channels
#os.system('iwconfig 
# You need to shutdown wlan0 first, unless you can not change the channel of mon0
commands.getstatus('ifconfig wlan0 down')
commands.getstatus('iwconfig mon0 channel 1')
#os.system('tcpdump -i mon0 -t -q -c 4 udp portrange 0-8000 and net 234')
#output = commands.getoutput('tcpdump -i mon0 -t -q -c 16 udp portrange 0-8000 and net 234')
#lines = output.split("\n")
#for line in lines:
p = Popen("tcpdump -i mon0 -t -q udp portrange 0-8000 and net 234", shell=True, stdout=PIPE)

ippre = []
ipcount = 0
length_list = []
for line in p.stdout:
	if line.find("length") == -1:
		continue
       	print line
        important_msg =	line.splitlines()[0].split(">")[1].lstrip()
	#print important_msg[1]
        iplen  = important_msg.split(" ")
	ip     = iplen[0].split(".")[0:4]
	length = iplen[-1]
	if ipcount != 0:
		if ippre == ip:
			ipcount = ipcount + 1
			length_list.append(length)
		else:
			ipcount = 0
			length_list = []
	else:
		ippre = ip
		ipcount = ipcount + 1
		length_list.append(length)
  	if ipcount == 4 and length_list==['515','514','513','512']:
		print "Received Guide Code and Exit"
		break
	print length
	print ip


def crc8():
	crcTable = []
	for value in range(256):
		remainder = value
		for bit in range(8):
			if (remainder&0x01)!=0:
				remainder = (remainder>>1)^0x8c
			else:	
				remainder = remainder>>1
		crcTable.append(remainder)
	return crcTable

#@param  [data, index]
def crc8_update(param, crcTable):
	value = 0x00    #init value
	data = param[0]^value
	value = (crcTable[data&0xff]^(value<<8))&0xff
	data = param[1]^value
	value = (crcTable[data&0xff]^(value<<8))&0xff
	return value 

crc_table = crc8()

def decoder_step1(param):
	print param
	data = param - 40
	out = data>>8
	if out==0:
		crc_value = (data&0x00f0)>>4
		print "crc_value: ", crc_value
		data_value = data&0x000f
		print "data_value: ", data_value
		return [out, crc_value, data_value]
	else:
		print "index: ", data&0x00ff
		return [out, data&0x00ff]

def crc8_check(param):
	print param
	#combine data
	if len(param[0])!=3 or len(param[2])!=3:
		return -1
	crc_value  = (param[0][1]<<4) + param[2][1]
	data_value = (param[0][2]<<4) + param[2][2]
	crc_value_data = crc8_update([data_value,param[1][1]], crc_table)
	if crc_value == crc_value_data:
		print "crc_value: %x  data_value: %x   crc_value_data: %x" %(crc_value, data_value, crc_value_data)
		print "crc succeed"
		return 1
	else:
		return -1

#@data_byte   divide into 3 16bit:
#  1st 16bit, 0x00 crc_high, data_high, 
#  2st 16bit, 0x01 index, 
#  3st 16bit, 0x00 crc_low, data_low, 
data_byte = [] 
#data_seq  =   #here 100 may be a potential bug
data_seq = {} #dict
for line in p.stdout:
	if line.find("length") == -1:
		continue
        important_msg =	line.splitlines()[0].split(">")[1].lstrip()
	#print important_msg[1]
        iplen  = important_msg.split(" ")
	ip     = iplen[0].split(".")[0:4]
	length = iplen[-1]
	de_value = decoder_step1(string.atoi(length, 10))
	data_byte.append(de_value)
        if len(data_byte) == 3:
		index_pattern = [data_byte[0][0], data_byte[1][0], data_byte[2][0]]
		if index_pattern==[0,1,0]:
			print data_byte
			if crc8_check(data_byte) == 1:
				if data_seq.has_key(data_byte[1][1])!=True:
					data_seq[data_byte[1][1]] = (data_byte[0][2]<<4) + data_byte[2][2]
				
			data_byte = []
		else:
			data_byte = data_byte[1:]
	print "data_seq: " ,data_seq 
	if ip!=ippre:
		continue
	print length, ip	
	
retval = p.wait()  		



