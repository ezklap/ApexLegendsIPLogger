from scapy.all import *
import time
import socket
import requests
import json
import platform    
import subprocess  
import ipaddress
import colorama

 
 
 
global IPSTACK_API_KEY
# Use this option if you want Geo Loction on the IP address get your free api key from https://ipstack.com
# their databases arent so up to date but its a nice feature if you want to enable it
IPSTACK_API_KEY = ''
 
colorama.init()
 
# Ping the server 1 time to get the response time from the server 
def ping(command):
	if ipaddress.ip_address(dest_ip).is_private == True or dest_ip in ip_list:
		return
	else:
		process = subprocess.Popen(command,stdout=subprocess.PIPE, shell=True)
		proc_stdout = process.communicate()[0].strip()
		#print(proc_stdout.decode(),sep=' ', end='\n', flush=True)
		response_time_str = str(re.findall(r'time=(\d+)\w', proc_stdout.decode())[0])
		response_time = int(response_time_str)
		seen = set(ip_list)
		if dest_ip not in seen:
			seen.add(dest_ip)
			ip_list.append(dest_ip)
	return response_time
 
 
 
 
# getting our local IP address
def get_ip():
	# get the local machines IP address
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		# doesn't even have to be reachable
		s.connect(('10.255.255.255', 1))
		IP = s.getsockname()[0]
	except:
		IP = '127.0.0.1'
	finally:
		s.close()
	return IP
 
global local_ip
local_ip = get_ip()
 
def pc(packet):
	if packet.proto == 17:
		udp = packet.payload
 
# Clear the console on the next updated IP address for a cleaner console output
def clear(): 
    print ("\x1b[2J")
 
 
 
def function_1():
	# looking for UDP packets sent to port 37005 Apex Legends servers 
	x = sniff(filter="udp and portrange 37005-38515", prn=pc, store=1, count=1) # Do not capture local IP UDP it captures local UDP packets
	y = x[0][IP].src
	z = x[0][IP].dst
	global dest_ip
	if local_ip in y:
		dest_ip = z
	else:
		dest_ip = y
	return dest_ip
 
 #  Geo Loction on the IP address you can get a free api key from their site just register and fill the global variable above on line 16
def ipStack(ip):
	if ipaddress.ip_address(ip).is_private == True: 
		return
	else:
		check_country = 'http://api.ipstack.com/{}?access_key={}&fields=country_name,country_code,city'.format(dest_ip,IPSTACK_API_KEY)
		response = requests.get(check_country)
		print('%r Game server IP: %r %s' % (strftime("%H:%M:%S", time.localtime()), dest_ip, response.json()))
 

# We check for updated IP addresses while playing different matches 
def check_ip(ip_check,ip2_check):
	current = ip_check
	new = ip2_check
	if ipaddress.ip_address(dest_ip).is_private == True or ip_check == ip2_check:
		return
	else:

		clear() 
		response_time = ping('ping -n 1 {} | FIND "TTL="'.format(dest_ip)) # pings the server
		if response_time == None:
			pass
		else:
			response_time_list.append(int(response_time))
		print('Game Server IP: {} Response time: {}ms'.format(current,response_time_list[-1]), sep=' ', end='\n', flush=True)
		if response_time is None:
			return
		elif response_time < 120:
			
			with open('Good-ApexServer.txt', 'a+') as the_file:
				the_file.seek(0)
				for line in the_file:
					if dest_ip in line:
						break
				else:
					the_file.write(dest_ip + '\n')
		else:
			with open('Lag-ApexServer.txt', 'a+') as the_file:
				the_file.seek(0)
				for line in the_file:
					if dest_ip in line:
						break
				else:
					the_file.write(dest_ip + '\n')
			if IPSTACK_API_KEY == '':
				return
			else:
				ipStack(dest_ip)
		#return current
	return current
 
 
 
ip_flag = '0.0.0.0'
global ip_list
ip_list = []
global response_time_list
response_time_list = []

# This is the main function 
while True:
	a = str(function_1()) 
	ip_flag = check_ip(a,ip_flag)  # function compares IP's if server changed or not
	time.sleep(20)
