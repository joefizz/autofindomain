#!/usr/bin/env python3

import os, sys, smtplib, ssl, configparser, shutil, itertools, threading, time, platform, subprocess, re
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
    by joefizz          |::.|   |::.. . / 
                        `---'   `------'  
                                          
"""
print(banner)

if os.path.isfile('config.ini') == False:
	print("config.ini file does not exist. Please copy config.ini.default to config.ini and update settings to suit")
	exit()

parser = configparser.ConfigParser()
parser.read('config.ini')

# email settings
port = parser['email']['port']
password = parser['email']['password']
sender_email = parser['email']['sender_email']
receiver_email = parser['email']['receiver_email']
email_server = parser['email']['email_server']
send_blank_emails = parser['email']['send_blank_emails'].lower()
send_attachments = parser['email']['send_attachments'].lower()

# local file settings
programs = parser['files']['programs']
# resolvers = parser['files']['resolvers']

# DNS updater settings
# source = parser['DNS']['source']

# NMAP Settings
nmap_on = parser['nmap']['nmap_on'].lower()
nmap_arguments = re.split(',| ',parser['nmap']['nmap_arguments'])
nmap_new = parser['nmap']['run_on_new_programs'].lower()

# Aquatone Settings
aquatone_on = parser['aquatone']['aquatone_on'].lower()
aquatone_web_path = parser['aquatone']['aquatone_web_path']
aquatone_new = parser['aquatone']['run_on_new_programs'].lower()


# Colour settings
colours = parser['colours']['colours'].lower()

# General settings
animation_on = parser['general']['animation_on'].lower()

# Set colours for output

if colours == 'true':
	tgood = '\033[32m'
	tnormal = '\033[33m'
	tbad = '\033[31m'
	talert = '\033[31m'
else:
	tgood = '\033[m'
	tnormal = '\033[m'
	tbad = '\033[m'
	talert = '\033[m'
tend = '\033[m'

# variable to record if current program is new (1 for mew, 0 for old)
new_program = 0

def subEnumerate(program, linux):
	print(tnormal, "--- Beginning findomain search of domains in " + program, tend)
	linux = linux
	f = open("programs/" + program + "/domains.txt")
	for domain in f:
		domain = domain.rstrip('\n')
		path="programs/"+program+"/"+domain


		done = False
		#here is the animation
		def animate():
			for c in itertools.cycle(['*    ', '**   ', '***  ', '**** ', '*****', ' ****', '  ***', '   **', '    *', '   **', '  ***', ' ****', '*****', '**** ', '***  ', '**   ']):
				if done:
					break
				sys.stdout.write('\r*** enumerating '+domain+' ' + c)
				sys.stdout.flush()
				time.sleep(0.1)

		t = threading.Thread(target=animate)
		t.daemon=True
		if animation_on == 'true':
			t.start()
		if linux == "true":
			os.system("./findomain-linux -q -t "+domain+" -u out.txt > /dev/null")
		if not linux == "true":
			os.system("findomain -q -t "+domain+" -u out.txt > /dev/null")
		os.system("sort -u out.txt > "+path+"_latest.txt")
		done = True
		print(tgood,"--- Latest subdomain results available in "+path+"_latest.txt",tend)

def subTrack(program):
	global new_program
	new_domain_count = 0
	new_domain_total = 0
	f = open("programs/" + program + "/domains.txt")
	for domain in f:
		domain = domain.rstrip('\n')
		path="programs/"+program+"/"+domain
		print(tnormal,"\n--- Comparing new discoveries to existing discoveries",tend)
		if os.path.isfile(path+"_all.txt") == False:
			print("First enum for this domain, no results to compare")
			os.system("cp "+path+"_latest.txt "+path+"_all.txt")
			print("Subdomains saved to "+path+"_all.txt")
			os.system("cp "+path+"_latest.txt "+path+"_new.txt")
			new_domain_total = sum(1 for line in open(path+"_new.txt"))
			new_program = 1
		else:
			os.system("comm -23 "+path+"_latest.txt "+path+"_all.txt > "+path+"_new.txt")
			new_domain_count = sum(1 for line in open(path+"_new.txt"))
			print(tgood,"--- "+str(new_domain_count)+" new subdomains for "+domain+" saved to "+path+"_new.txt",tend)
			new_domain_total += new_domain_count
			os.system("cp "+path+"_all.txt "+path+"_temp.txt")
			os.system("cat "+path+"_new.txt >> "+path+"_temp.txt")
			os.system("sort -u "+path+"_temp.txt > "+path+"_all.txt")
		print(tgood,"Newly discovered subdomains added to all",tend)
	os.system("echo 'New subdomains for "+program+":' > programs/"+program+"/report.txt")
	os.system("cat programs/"+program+"/*_new.txt >> programs/"+program+"/report.txt")
	return new_domain_total

def subNmap(program):
	print(tnormal,"--- beginning NMAP scans of all new subdomains discovered for "+program,tend)
	f = open("programs/" + program + "/domains.txt")
	port_count = 0
	for domain in f:
		newSubdomains = []
		domain = domain.rstrip('\n')
		path="programs/"+program+"/"+domain
		s = open(path+"_new.txt")
		for subdomain in s:
			subdomain=subdomain.rstrip('\n')
			newSubdomains.append(subdomain)

		for subdomain in newSubdomains:
			nmap_args = nmap_arguments.copy()
			done = False
			#here is the animation
			def animate():
				for c in itertools.cycle(['*    ', '**   ', '***  ', '**** ', '*****', ' ****', '  ***', '   **', '    *', '   **', '  ***', ' ****', '*****', '**** ', '***  ', '**   ']):
					if done:
						break
					sys.stdout.write('\r*** port scanning '+subdomain+' ' + c)
					sys.stdout.flush()
					time.sleep(0.1)

			t = threading.Thread(target=animate)
			t.daemon=True
			nmap_args.append('-oA')
			nmap_args.append(path+'_nmap')
			nmap_args.append(subdomain)
			nmap_string = ' '.join(nmap_args)
			print('\n--- attempting command: nmap' + nmap_string)
			if animation_on == 'true':
				t.start()
			try:
				FNULL = open(os.devnull, 'w')
				proc = subprocess.call(['nmap']+nmap_args, stdout=FNULL, stderr=subprocess.STDOUT)
			except OSError as e:
				print (e.output)
			shutil.move(path+'_nmap.nmap', path+'_nmap.txt')
			file = open(path+'_nmap.gnmap', "r")
			for line in file:
				line = line.lower()
				if re.search('open', line):
					port_count += 1
			done = True

			print(tgood,"Latest nmap results available in "+path+"_nmap.{txt,gnmap,xml}",tend)
	return port_count

def subAquatone(program):
	print(tgood,"--- beginning aquatone enumeration of all new subdomains discovered for "+program,tend)

	f = open("programs/" + program + "/domains.txt")
	for domain in f:
		newSubdomains = []
		domain = domain.rstrip('\n')
		path="programs/"+program+"/"+domain
		s = open(path+"_new.txt")
		for subdomain in s:
			subdomain=subdomain.rstrip('\n')
			newSubdomains.append(subdomain)

		for subdomain in newSubdomains:
			done = False
			#here is the animation
			def animate():
				for c in itertools.cycle(['*    ', '**   ', '***  ', '**** ', '*****', ' ****', '  ***', '   **', '    *', '   **', '  ***', ' ****', '*****', '**** ', '***  ', '**   ']):
					if done:
						break
					sys.stdout.write('\r*** aquatoning '+subdomain+' ' + c)
					sys.stdout.flush()
					time.sleep(0.1)

			t = threading.Thread(target=animate)
			t.daemon=True
			if animation_on == 'true':
				t.start()
			try:
				cat = subprocess.Popen(('cat', path+'_nmap.xml'), stdout=subprocess.PIPE)
				aqua = subprocess.call(('aquatone', '-nmap', '-out', path, '-silent'), stdin=cat.stdout)
			except OSError as e:
				print (e.output)
			try:
				shutil.move(path+'/aquatone_report.html', aquatone_web_path+'/'+subdomain+'_aquatone_report.html')
			except:
				Print(tbad,"Error copying file",tend)
			done = True


			print(tgood,"Latest aquatone results available in "+aquatone_web_path,tend)

def subReport(program):
	print(tnormal,"--- sending results email to " + receiver_email,tend)
	fp = open("programs/"+program+"/report.txt", "r")
	mail_content = fp.read()
	files = "programs/"+program
	filenames = [os.path.join(files, f) for f in os.listdir(files)]
	for x in range(len(filenames)): 
		if not os.path.isdir(x):
			print("Filename: "+filenames[x])
	msg = MIMEMultipart()
	msg['Subject'] = "findomain results for " + program
	msg['From'] = sender_email
	msg['To'] = receiver_email
	msg.attach(MIMEText(mail_content, 'plain'))
	if send_attachments == "true":
		for file in filenames:
			if not os.path.isdir(file):
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

def main():

	global new_program

	if sys.version_info <= (3, 0):
		print(tbad,"This script requires Python 3.4+\n",tend)
		sys.exit(1)

	if nmap_on == 'true':
		try:
			FNULL = open(os.devnull, 'w')
			proc = subprocess.call(['nmap','--version'],stdout=FNULL, stderr=subprocess.STDOUT)
		except OSError as e:
			print (tbad,'*** Nmap is not installed in path, install nmap to path or disable port scanning in config.ini\n',tend)
			exit()

	if aquatone_on == 'true':
		try:
			FNULL = open(os.devnull, 'w')
			proc = subprocess.call(['aquatone','-version'],stdout=FNULL, stderr=subprocess.STDOUT)
		except OSError as e:
			print (tbad,'*** Aquatone is not installed in path, install nmap to path or disable port scanning in config.ini\n',tend)
			exit()
		
		try:
			FNULL = open(os.devnull, 'w')
			proc = subprocess.call(['ls',aquatone_web_path],stdout=FNULL, stderr=subprocess.STDOUT)
		except OSError as e:
			print (tbad,'*** Aquatone HTML output folder does not exist.  Check aquatone_web_path in config.ini\n',tend)
			exit()


	if platform.system() == "Linux":
		linux = "true"
	elif platform.system() == "Darwin":
		linux = "false"
	else:
		print(tbad,"AutoFD currently only works on mac and Linux.",tend)
		exit()

	if len(sys.argv) < 2:
		print(tgood+"autofd usage\n\n./autofd.py <option>\n\nOptions: enum, add, del, list, email, purge\n",tend)
		exit()

	if (sys.argv[1]).lower() == "enum" or (sys.argv[1]).lower() == "program":
		if os.path.isfile(programs) == False:
			print(tbad,"No programs to enumerate.  Have you run `./autofindomain.py add`  ?",tend)
			exit()
		if linux == "true":
			print(tnormal,"--- Downloading latest version of findomain",tend)
			if os.path.isfile("./findomain-linux"):
				os.system("rm -f ./findomain-linux")
			os.system("wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux -q --show-progress; chmod +x findomain-linux")
		p = open(programs)

		if (sys.argv[1]).lower() == "enum":
			for program in p:
				program = program.rstrip('\n')
				print("\n\n*** Program = " + program)
				subEnumerate(program,linux)
				new_domains = subTrack(program)
				print("--- send_blank_emails: "+send_blank_emails)
				print("--- new_domains: "+str(new_domains))
				port_count = 0
				if nmap_on == 'true' and new_domains > 0:
					if new_program == 0 or nmap_new == 'true':
						port_count = subNmap(program)
					if aquatone_on == 'true' and port_count > 0:
						if new_program == 0 or aquatone_new == 'true':
							subAquatone(program)
				if send_blank_emails == 'false' and new_domains > 0:
					subReport(program)
				new_program = 0

		elif (sys.argv[1]).lower() == "program":
			program = sys.argv[2].rstrip('\n')

			file = open(programs, "r")
			count = 0
			for line in file:
			     if re.search(program, line):
			         count+=1
			if count > 0:
				print(tbad,program+" does not exist in programs.txt, add with './autofd add <program name>'",tend)
				exit()

			print("\n\n *** Program = " + program)
			subEnumerate(program,linux)
			new_domains = subTrack(program)
			print("--- send_blank_emails: "+send_blank_emails)
			print("--- new_domains: "+str(new_domains))
			port_count = 0
			if nmap_on == 'true' and new_domains > 0:
				print('*** new_program = '+str(new_program))
				if new_program == 0 or nmap_new == 'true':
					port_count = subNmap(program)
				if aquatone_on == 'true' and port_count > 0:
					if new_program == 0 or aquatone_new == 'true':
						subAquatone(program)
			if send_blank_emails == 'false' and new_domains > 0:
				subReport(program)

		exit()


	if (sys.argv[1]) == "add":
		newProgram = sys.argv[2].rstrip('\n')
		print(tnormal,"Adding new program: " + newProgram,tend)
		if os.path.isfile(programs) == False:
			Path(programs).touch()
		# Check program does not already exist in programs.txt and add it if not
		p = open(programs)
		for program in p:
			program = program.rstrip('\n')
			if program == newProgram:
				print("Program " + newProgram +" already exists")
				exit()
		p.close()
		p = open(programs, 'a')
		p.write("\n"+newProgram)
		p.close()
		# Check if program directory already exists and add it if not
		if os.path.isfile("./programs/"+newProgram) == False:
			os.makedirs("./programs/" + newProgram)
		Path("./programs/"+newProgram+"/domains.txt").touch()
		print(tgood,newProgram+" added. Please add root domains to ./programs/"+newProgram+"/domains.txt",tend)
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
		print(talert,"Purging all programs that are not in programs.txt\n\n*****  THERE IS NO COMING BACK FROM THIS - ALL DATA FOR DELETED PROGRAMS WILL BE ERASED *****",tend)
		agree = input("type YES to continue: ")
		count = 0
		if agree == "YES":
			folderSet = set(line.strip() for line in open(programs))
			for folder in os.listdir("./programs"):
				if os.path.isdir("./programs/"+folder):
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
		print(tnormal,"Current programs that will be enumerated:",tend)
		p = open(programs)
		for program in p:
			program = program.rstrip('\n')
			print("\n"+program)
			f = open("./programs/"+program+"/domains.txt")
			for domain in f:
				print("    "+domain.rstrip('\n'))
		exit()

	#if sys.argv[1] == "dns":
	#	print("Updating resolvers")
	#	os.system('curl '+source+' -s | sort -R | tail -n 25 > ./resolvers.txt')
	#	exit()

	if sys.argv[1] == 'email':
		print(tgood,"--- sending test email to " + receiver_email,tend)
		msg = MIMEText("Test email from autofindomain")
		msg['Subject'] = "Test email from autofindomain"
		msg['From'] = sender_email
		msg['To'] = receiver_email
		context = ssl.create_default_context()
		with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
				server.login(sender_email, password)
				server.sendmail(sender_email, receiver_email, msg.as_string())	

if __name__ == "__main__":
    main()
