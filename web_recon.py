#!/usr/local/bin/python2.7


import string
#import urllib2
import subprocess
import os
import sys
#import time
import threadpool
import argparse

def nmap_read (file_name):
	file_open = open(file_name,'r')
	nmap_file = file_open.readlines()
	file_open.close()
	return nmap_file

def nmap_parse (nmap_data,parser_type):
	nmap_return = []
	
	for host_info in nmap_data: #go through line by line and parse out hosts with open ports
		if host_info.find(parser_type) <> -1: # check to see if host has open closed filtered ports

			hostip = host_info.split(" ")[1]
			temp = host_info.split(" ")
			
			ports = ""
			for temp_ports in temp:
				if temp_ports.find(parser_type) <> -1:
					ports = ports + "," +  temp_ports.split("/")[0] 
					ports = ports.lstrip(",")	
                        nmap_return.append(hostip + "," + ports)
        
        return nmap_return



def nmap_scan (nmap_command_line,filename,parse_string):

	nmap_command_line = nmap_command_line + " -oA " + filename
	print nmap_command_line
	print nmap_command_line.split(" ")	
	subprocess.call(nmap_command_line.split(" "))
	nmapgrep = nmap_read(filename +".gnmap")
	
	return nmap_parse(nmapgrep,parse_string)


def make_thumbs (nmap_file,report_dir,thumb_check):
	if thumb_check == "yes":
		print nmap_file
		read_file = nmap_read(nmap_file)
		http_thumbs = nmap_parse(read_file,"/open/tcp//http//")
		print http_thumbs
		pool = threadpool.ThreadPool(max_threads)
		for thumbs in http_thumbs:
			hostname = thumbs.split(",")[0]
			count = 1
			
			while count < len(thumbs.split(",")):			
				port = thumbs.split(",")[count]
				thumb_nail_process = "gnome-web-print http://" + hostname + ":"+port+" "+report_dir+hostname+"_"+port+".png --force -t 3"
				print thumb_nail_process
				pool.add_task(subprocess.call,(thumb_nail_process.split(" "),))		
				#subprocess.call(thumb_nail_process.split(" "))
				count = count + 1
		pool.start_workers()
		pool.wait()
		http_thumbs = nmap_parse(read_file,"/open/tcp//ssl")
		print http_thumbs
		pool = threadpool.ThreadPool(max_threads)
		for thumbs in http_thumbs:
			hostname = thumbs.split(",")[0]
			count = 1
					 
			while count < len(thumbs.split(",")):
				port = thumbs.split(",")[count]
				thumb_nail_process = "gnome-web-print https://" + hostname + ":"+port+" "+report_dir+hostname+"_"+port+".png --force -t 3"
				print thumb_nail_process		
				pool.add_task(subprocess.call,(thumb_nail_process.split(" "),))
				count = count + 1
		pool.start_workers()
		pool.wait()
			
		http_thumbs = nmap_parse(read_file,"/open/tcp//https/")
		print http_thumbs
		pool = threadpool.ThreadPool(max_threads)
		for thumbs in http_thumbs:
			hostname = thumbs.split(",")[0]
			count = 1
		 	
			
			while count < len(thumbs.split(",")):
				port = thumbs.split(",")[count]
				thumb_nail_process = "gnome-web-print https://" + hostname + ":"+port+" "+report_dir+hostname+"_"+port+".png --force -t 3"
				print thumb_nail_process
		
				#subprocess.call(thumb_nail_process.split(" "))
				pool.add_task(subprocess.call,(thumb_nail_process.split(" "),))
				count = count + 1
		pool.start_workers()
		pool.wait()
 	
	return 0
#replace thumbs with something else in this function
def dirby_hunt(nmap_file,wordlist,report_dir,dirb_base,dirb_check):
	if dirb_check == "yes":
		print nmap_file
		read_file = nmap_read(nmap_file)
		http_thumbs = nmap_parse(read_file,"/open/tcp//http//")
		print http_thumbs
		pool = threadpool.ThreadPool(max_threads)
		for thumbs in http_thumbs:
			hostname = thumbs.split(",")[0]
			count = 1
			
			while count < len(thumbs.split(",")):
				port = thumbs.split(",")[count]
				dirb_process = dirb_location + " http://" + hostname + ":"+ port + " "+ wordlist+ " -o"+report_dir+hostname+"_"+port+".txt" + dirb_base
				print dirb_process		
				pool.add_task(subprocess.call,(dirb_process.split(" "),))
				count = count + 1 
		pool.start_workers()
		pool.wait()
 	
		http_thumbs = nmap_parse(read_file,"/open/tcp//ssl")
		print http_thumbs
		pool = threadpool.ThreadPool(max_threads)
		for thumbs in http_thumbs:
			hostname = thumbs.split(",")[0]
			count = 1
			while count < len(thumbs.split(",")):
				port = thumbs.split(",")[count]
				dirb_process = dirb_location + " https://" + hostname + ":"+port+" "+wordlist+" -o "+report_dir+hostname+"_"+port+".txt"
				print dirb_process		
				#subprocess.call(dirb_process.split(" "))
				pool.add_task(subprocess.call,(dirb_process.split(" "),))
				count = count + 1
		pool.start_workers()
		pool.wait()
 	
		http_thumbs = nmap_parse(read_file,"/open/tcp//https")
		print http_thumbs
		pool = threadpool.ThreadPool(max_threads)
		for thumbs in http_thumbs:
			hostname = thumbs.split(",")[0]
			count = 1
			while count < len(thumbs.split(",")):
				port = thumbs.split(",")[count]
				dirb_process = dirb_location + " https://" + hostname + ":"+port+" "+wordlist+" -o "+report_dir+hostname+"_"+port+".txt"
				print dirb_process		
				#subprocess.call(dirb_process.split(" "))
				pool.add_task(subprocess.call,(dirb_process.split(" "),))
				count = count + 1
		pool.start_workers()
		pool.wait()
 
	return 0

#have to review this
def nmap_service_scan(nmap_base,results,report_dir,extension):
	print results
	parser_string = "http"
	hostnames_return = []
	for scan in results:
		print scan
		hostname = scan.split(",")[0]
		hostnames_return.append(hostname)
		port = scan.split(",")[1]
		print len(scan.split(","))
		if len(scan.split(",")) > 2:
			#port = ""
			count = 2
			while count < len(scan.split(",")):
				print count
				port = port + "," + scan.split(",")[count]
				print port
				count = count + 1
		print port
		
		if not os.path.exists(report_dir + hostname):		
			os.mkdir(report_dir + hostname)		
		nmap_scan(nmap_base +"-sV " + hostname + " " + "-p " + port,report_dir+hostname+"/"+hostname+extension,parser_string)
	return hostnames_return		
	

def create_reports(): #not sure how i'm going to this yet but have a few ideas
	return 0



def fast_scan (nmap_base, report_dir, initial_nmap,network_range,full_nmap,wordlist,dirb_base,thumb_check,dirb_check):
	filename = network_range
	if not os.path.exists(report_dir): #make sure we have some reporting direcotires
  		os.mkdir(report_dir)
	if not os.path.exists(report_dir + "nmap/"):
  		os.mkdir(report_dir + "nmap")	
	if not(network_range.find("/") == -1):
		filename = network_range.split("/")[0]
	if not(network_range.find(" ") == -1):
		if not(network_range.find("-iL") == -1):
			filename = network_range.split(" ")[1] 
		else:
			filename = network_range.split(" ")[0]		
	results = nmap_scan(initial_nmap +" "+ network_range,report_dir + "nmap/" + filename + "_nmap-80.443","open")	
	print results
	host_list = nmap_service_scan(nmap_base,results,report_dir,"_80.443")	
	print host_list	
	#sleep(30)
	pool = threadpool.ThreadPool(max_hosts)
	for host in host_list:
		print host
		if not os.path.exists(report_dir + host +"/"+"images/"):
			os.mkdir(report_dir + host + "/" + "images/")
		pool.add_task(make_thumbs,(report_dir + host + "/"+host+"_80.443.gnmap",report_dir + host + "/" + "images/",thumb_check))
		#make_thumbs(report_dir + host + "/"+host+"_80.443.gnmap",report_dir + host + "/" + "images/",thumb_check)
		if not os.path.exists(report_dir + host +"/"+"dirb_report/"):
			os.mkdir(report_dir + host + "/" + "dirb_report/")
		pool.add_task(dirby_hunt,(report_dir + host + "/"+host+"_80.443.gnmap",wordlist,report_dir + host + "/" + "dirb_report/",dirb_base,dirb_check,))
		#dirby_hunt(report_dir + host + "/"+host+"_80.443.gnmap",wordlist,report_dir + host + "/" + "dirb_report/",dirb_base,dirb_check)		
	pool.start_workers()
	pool.wait()
 
	
	return 0

def internal_scan(nmap_base, report_dir, initial_nmap,network_range,full_nmap,wordlist,dirb_base,thumb_check,dirb_check):
	filename = network_range	
	if not(network_range.find("/") == -1):
		filename = network_range.split("/")[0]
	if not(network_range.find(" ") == -1):
		if not(network_range.find("-iL") == -1):
			filename = network_range.split(" ")[1] 
		else:
			filename = network_range.split(" ")[0]
	fast_scan(nmap_base, report_dir, initial_nmap,network_range,full_nmap,wordlist,dirb_base,thumb_check,dirb_check)
	nmap_grep = nmap_read(report_dir + "nmap/" + filename + "_nmap-80.443.gnmap")
	host_temp = nmap_parse(nmap_grep,"80/open")
	host_temp = host_temp + nmap_parse(nmap_grep,"80/closed")
	net_range2 = ""	
	for temp in host_temp:
		net_range2 = net_range2 + " " + temp.split(",")[0].strip()
		
	net_range2 = net_range2.strip()	
	
	full_scan (nmap_base, report_dir, initial_nmap,net_range2,full_nmap,wordlist,dirb_base,thumb_check,dirb_check)
	return 0
	
def external_scan(nmap_base, report_dir, initial_nmap,network_range,full_nmap,wordlist,dirb_base,thumb_check,dirb_check):
	fast_scan(nmap_base, report_dir, initial_nmap,network_range,full_nmap,wordlist,dirb_base,thumb_check,dirb_check)
	full_scan(nmap_base, report_dir, initial_nmap,network_range,full_nmap,wordlist,dirb_base,thumb_check,dirb_check)
	return 0

def full_scan (nmap_base, report_dir, initial_nmap,network_range,full_nmap,wordlist,dirb_base,thumb_check,dirb_check):
	if not(network_range.find("/") == -1):
		filename = network_range.split("/")[0]
	if not(network_range.find(" ") == -1):
		if not(network_range.find("-iL") == -1):
			filename = network_range.split(" ")[1] 
		else:
			filename = network_range.split(" ")[0]	
	results = nmap_scan(full_nmap +" "+ network_range,report_dir + "nmap/" + filename + "_nmap-full","open")	
		
	host_list = nmap_service_scan(nmap_base,results,report_dir,"_nmap-full")
	pool = threadpool.ThreadPool(max_hosts)
	for host in host_list:
		print host
		if not os.path.exists(report_dir + host +"/"+"images/"):
			os.mkdir(report_dir + host + "/" + "images/")
		pool.add_task(make_thumbs,(report_dir + host + "/"+host+"_nmap-full.gnmap",report_dir + host + "/" + "images/",thumb_check))
		if not os.path.exists(report_dir + host +"/"+"dirb_report/"):
			os.mkdir(report_dir + host + "/" + "dirb_report/")
		pool.add_task(dirby_hunt,(report_dir + host + "/"+host+"_nmap-full.gnmap",wordlist,report_dir + host + "/" + "dirb_report/",dirb_base,dirb_check))
	pool.start_workers()
	pool.wait()
		
	return 0

def file_scan(nmap_base, report_dir, initial_nmap,network_range,full_nmap,wordlist,dirb_base,thumb_check,dirb_check):
	if not os.path.exists(report_dir):
		os.mkdir(report_dir)
	if not os.path.exists(report_dir + "images/"):
		os.mkdir(report_dir + "images/")
	make_thumbs (network_range,report_dir+"images/",thumb_check)
	if not os.path.exists(report_dir + "dirb_reports/"):
		os.mkdir(report_dir + "dirb_reports/")
	dirby_hunt(network_range,wordlist,report_dir+"dirb_reports/",dirb_base,dirb_check)
	
	return 0
def main ():
	config_file = nmap_read("config/scanner.config")
	
	for line in config_file:
		if not(line.find("nmap_base") == -1):
			nmap_base = line.split("\"")[1]
		if not(line.find("report_dir") == -1):
			report_dir = line.split("\"")[1]
		if not(line.find("initial_nmap") == -1):
			initial_nmap = nmap_base + line.split("\"")[1]
		if not(line.find("full_nmap") == -1):
			full_nmap = nmap_base + line.split("\"")[1]
		if not(line.find("wordlist") == -1):
			wordlist = line.split("\"")[1]
		if not(line.find("dirb_base") == -1):
			dirb_base = line.split("\"")[1]
		if not(line.find("thumb_check") == -1):
			thumb_check = line.split("\"")[1]
		if not(line.find("dirb_check") == -1):
			dirb_check = line.split("\"")[1]
		if not(line.find("max_ports") == -1):
			global max_threads
			max_threads = int(line.split("\"")[1])
		if not(line.find("max_hosts") == -1):
			global max_hosts
			max_hosts = int(line.split("\"")[1])
		if not(line.find("dirb_location") == -1):
			global dirb_location
			dirb_location = line.split("\"")[1]
#	print dirb_check
#	print thumb_check
	#aaaaa

			
	parser = argparse.ArgumentParser(prog='webrecon -h',
					  description='''Basic webrecon program.  Copyright (C) 2012 <Offwidth>''',
					  epilog='''    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.''')
	parser.add_argument ('-t',action='store',dest='scan_type',help='Type of scan to perform: internal,external,quick,file')
	parser.add_argument('-n',action='store',dest='network_range',help='Network range to scan or file name in network scan')
	parser.add_argument('-p',action='store',dest='report_dir',help='Project name to be stored in report dir')
#	parser.add_argument('-c', help="WebRecon Copyright (C) 2012 Offwidth")	
	command_line = parser.parse_args()
	network_range = command_line.network_range
	report_dir = report_dir + command_line.report_dir + "/"
	scan_type = command_line.scan_type.lower()
	#if network_range == NoneType:
	#	print "No Network Range Defined"
	#	exit	
	#nmap_base = "nmap -PN -n -T4 -vvvvv "
	#report_dir = "reports/test/"
	#report_dir = report_dir + "test/"
	#initial_nmap = nmap_base + "-p 80,443"
	#network_range = "192.168.1.1/24"
	#full_nmap  = nmap_base + "-p1-65535"	
	#wordlist = "dirb/wordlists/quick_test.txt"
	#dirb_base = ""
	#fast_scan (nmap_base, report_dir, initial_nmap,network_range,full_nmap,wordlist,dirb_base)
	if scan_type == "external":	
		external_scan(nmap_base, report_dir, initial_nmap,network_range,full_nmap,wordlist,dirb_base,thumb_check,dirb_check)
	elif scan_type == "internal":
		internal_scan(nmap_base, report_dir, initial_nmap,network_range,full_nmap,wordlist,dirb_base,thumb_check,dirb_check)
	elif scan_type == "quick":
		fast_scan(nmap_base, report_dir, initial_nmap,network_range,full_nmap,wordlist,dirb_base,thumb_check,dirb_check)
	elif scan_type == "file":
		file_scan(nmap_base, report_dir, initial_nmap,network_range,full_nmap,wordlist,dirb_base,thumb_check,dirb_check)
		exit()
	else:
		print "no scan type"
	return 0
	

try :
	main()
except TypeError:
	print "Please type -h for help"

