#!/usr/bin/env python3

import os, sys, smtplib, ssl, configparser, shutil
from email.mime.text import MIMEText 
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path

banner = """
              __         _______ ______   
 .---.-.--.--|  |_.-----|   _   |   _  \  
 |  _  |  |  |   _|  _  |.  1___|.  |   \ 
 |___._|_____|____|_____|.  __) |.  |    \ 
                        |:  |   |:  1    /
                        |::.|   |::.. . / 
                        `---'   `------'  
                                          
"""
print(banner)

if os.path.isfile('config.ini') == False:
	print("config.ini file does not exist. Please copy config.ini.default to config.ini and update settings to suit")
	exit()

parser = configparser.ConfigParser()
parser.read('config.ini')

# OS settings
linux = parser['OS']['linux'].lower()

# email settings
port = parser['email']['port']
password = parser['email']['password']
sender_email = parser['email']['sender_email']
receiver_email = parser['email']['receiver_email']

# local file settings
programs = parser['files']['programs']
# resolvers = parser['files']['resolvers']

# DNS updater settings
# source = parser['DNS']['source']

def subEnumerate(program):
	print("**** Beginning findomain search of domains in " + program)
	f = open("programs/" + program + "/domains.txt")
	for domain in f:
		domain = domain.rstrip('\n')
		path="programs/"+program+"/"+domain
		if linux == "true":
			os.system("./findomain -q -t "+domain+" -u out.txt")
		if not linux == "true":
			os.system("findomain -q -t "+domain+" -u out.txt")
		os.system("sort -u out.txt > "+path+"_latest.txt")
		print("Latest subdomain results available in "+path+"_latest.txt")


def subTrack(program):
	f = open("programs/" + program + "/domains.txt")
	for domain in f:
		domain = domain.rstrip('\new')
		path="programs/"+program+"/"+domain
		print("Comparing new discoveries to existing discoveries")
		if os.path.isfile(path+"_all.txt") == False:
			print("First enum for this domain, no results to compare")
			os.system("cp "+path+"_latest.txt "+path+"_all.txt")
			print("Subdomains saved to "+path+"_all.txt")
			exit()
		os.system("comm -23 "+path+"_latest.txt "+path+"_all.txt > "+path+"_new.txt")
		print("New subdomains for "+domain+" saved to "+path+"_new.txt")
	os.system("echo 'New subdomains for "+program+":' > programs/"+program+"/report.txt")
	os.system("cat programs/"+program+"/*_new.txt >> programs/"+program+"/report.txt")

"""
def subReport(program):
	print("**** sending results email to " + receiver_email)
	fp = open("programs/"+program+"/report.txt", "r")
	msg = MIMEText(fp.read())
	fp.close()
	msg['Subject'] = "findomain results for " + program
	msg['From'] = sender_email
	msg['To'] = receiver_email
	context = ssl.create_default_context()
	with smtplib.SMTP_SSL(email_server, port, context=context) as server:
			server.login(sender_email, password)
			server.sendmail(sender_email, receiver_email, msg.as_string())
"""

def subReport(program):
	print("**** sending results email to " + receiver_email)
	fp = open("programs/"+program+"/report.txt", "r")
	mail_content = fp.read()
	files = "programs/"+program
	filenames = [os.path.join(files, f) for f in os.listdir(files)]
	for x in range(len(filenames)): 
		print("Filename: "+filenames[x])
	msg = MIMEMultipart()
	msg['Subject'] = "findomain results for " + program
	msg['From'] = sender_email
	msg['To'] = receiver_email
	msg.attach(MIMEText(mail_content, 'plain'))
	for file in filenames:
		label = file.split("/")[2]
		part = MIMEBase('application', 'octet-stream')
		part.set_payload(open(file, 'rb').read())
		encoders.encode_base64(part)
		part.add_header('Content-Disposition', 'attachment; filename='+label)
		msg.attach(part)
		context = ssl.create_default_context()
	with smtplib.SMTP_SSL(email_server, port, context=context) as server:
		server.login(sender_email, password)
		server.sendmail(sender_email, receiver_email, msg.as_string())



if len(sys.argv) < 2:
	print("autofd usage\n\n./autofd.py <option>\n\nOptions: enum, add, del, list, email, purge\n")
	exit()

print(type(linux))

if linux == "true":
	os.system("wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux; chmod +x findomain-linux")

if (sys.argv[1]) == "enum":
	if os.path.isfile(programs) == False:
		print("No programs to enumerate.  Have you run `./autofindomain.py add`  ?")
		exit()
	p = open(programs)
	for program in p:
		program = program.rstrip('\n')
		print("program = " + program)
		subEnumerate(program)
		subTrack(program)
		subReport(program)
	p.close()
	exit()

if (sys.argv[1]) == "add":
	newProgram = sys.argv[2].rstrip('\n')
	print("Adding new program: " + newProgram)
	if os.path.isfile(programs) == False:
		Path(programs).touch()
	# Check program does not already exist in programs.txt and add it if not
	p = open(programs)
	for program in p:
		if program == newProgram:
			print("Program '" + newProgram +"' already exists")
			exit()
	p.close()
	p = open(programs, 'a')
	p.write("\n"+newProgram)
	p.close()
	# Check if program directory already exists and add it if not
	if os.path.isfile("programs/"+newProgram) == False:
		os.makedirs("./programs/" + newProgram)
	Path("./programs/"+newProgram+"/domains.txt").touch()
	print(newProgram+" added. Please add root domains to ./programs/"+newProgram+"/domains.txt")
	with open(programs) as filehandle:
		lines = filehandle.readlines()
	with open(programs, 'w') as filehandle:
		lines = filter(lambda x: x.strip(), lines)
		filehandle.writelines(lines)

if sys.argv[1] == "del":
	if os.path.isfile(programs) == False:
		print("No programs to delete")
		exit()
	program = sys.argv[2]
	print("Deleting "+ program +" from programs.txt.  This will not remove the data folder from ./programs/")
	with open(programs, "r") as p:
		lines = p.readlines()
	with open(programs, "w") as p:
		for line in lines:
			if line.strip('\n') != program:
				p.write(line)

if sys.argv[1] == "purge":
	print("Purging all programs that are not in programs.txt\n\n*****  THERE IS NO COMING BACK FROM THIS - ALL DATA FOR DELETED PROGRAMS WILL BE ERASED *****")
	agree = input("type YES to continue: ")
	count = 0
	if agree == "YES":
		folderSet = set(line.strip() for line in open(programs))
		for folder in os.listdir("./programs"):
			if folder not in folderSet:
				print("Deleting " + folder)
				shutil.rmtree("./programs/"+folder)
				count+=1
	print("Deleted "+str(count)+" directories from ./programs/")
	exit()

if sys.argv[1] == "list":
	if os.path.isfile(programs) == False:
		print("No programs to list.  add with add")
		exit()
	print("Current programs that will be enumerated:")
	p = open(programs)
	for program in p:
		print(program.strip('\n'))
	exit()

#if sys.argv[1] == "dns":
#	print("Updating resolvers")
#	os.system('curl '+source+' -s | sort -R | tail -n 25 > ./resolvers.txt')
#	exit()

if sys.argv[1] == 'email':
	print("**** sending test email to " + receiver_email)
	msg = MIMEText("Test email from autofindomain")
	msg['Subject'] = "Test email from autofindomain"
	msg['From'] = sender_email
	msg['To'] = receiver_email
	context = ssl.create_default_context()
	with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
			server.login(sender_email, password)
			server.sendmail(sender_email, receiver_email, msg.as_string())	
