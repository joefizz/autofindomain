#!/usr/bin/env python3

import os, sys, smtplib, ssl, configparser, shutil, itertools, threading, time, platform, subprocess, re, stat
import xml.etree.ElementTree as ET
from datetime import datetime
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

now=datetime.now()
timestamp = now.strftime("%d-%m-%Y_%H-%M-%S")
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
aquatone_nmap = parser['aquatone']['aquatone_nmap'].lower()
aquatone_http_timeout = parser['aquatone']['aquatone_http_timeout']
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

print(tnormal,"Timestamp: "+timestamp,tend)

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
	print(tnormal,"--- Removing historic nmap files from "+program+" folder.",tend)
	dir = "./programs/"+program
	for f in os.listdir(dir):
		if re.search('nmap', f):
			print("    deleting: "+f)
			os.remove(os.path.join(dir, f))	

	print(tnormal,"--- Beginning NMAP scans of all new subdomains discovered for "+program,tend)
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
			nmap_args.append('programs/'+program+'/'+subdomain+'_nmap_'+timestamp)
			nmap_args.append(subdomain)
			nmap_string = ' '.join(nmap_args)
			print('\n--- attempting command: nmap ' + nmap_string)
			if animation_on == 'true':
				t.start()
			try:
				FNULL = open(os.devnull, 'w')
				proc = subprocess.call(['nmap']+nmap_args, stdout=FNULL, stderr=subprocess.STDOUT)
			except OSError as e:
				print (e.output)
			shutil.move('programs/'+program+'/'+subdomain+'_nmap_'+timestamp+'.nmap', path+'_nmap_'+timestamp+'.txt')
			file = open('programs/'+program+'/'+subdomain+'_nmap_'+timestamp+'.gnmap', "r")
			for line in file:
				line = line.lower()
				if re.search('open', line):
					port_count += 1
			done = True

			print(tgood,"Latest nmap results available in "+path+"_nmap_"+timestamp+".{txt,gnmap,xml}",tend)
	xmlFiles = []

	dir = "./programs/"+program
	for f in os.listdir(dir):
		if f.lower().endswith('_nmap_'+timestamp+'.xml'):
			xmlFiles.append(os.path.join(dir, f))

	xmlMerge(xmlFiles, program)

	return port_count

def xmlMerge(xmlFiles, program):

	hosts_count = 0

	# Check to ensute we have work to do
	if not xmlFiles:
		print("No XML files were found ... No work to do")
		exit()

	# Create the Merged filename
	path="programs/"+program

	mergeFile = path+"/nmap_merged_" + timestamp + ".xml"

	# Add Header to mergefile
	nMap_Header  = '<?xml version="1.0" encoding="UTF-8"?>\n'
	nMap_Header += '<!DOCTYPE nmaprun>\n'
	nMap_Header += '<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n'
	nMap_Header += '<nmaprun scanner="nmap" args="nmap -T4 -&#45;top-ports 10 -oA programs/nz420/nz420.com_nmap_03-07-2020_15-42-57 nz420.com" start="1593787378" startstr="Fri Jul  3 15:42:58 2020" version="7.80" xmloutputversion="1.04">\n'
	nMap_Header += '<scaninfo type="connect" protocol="tcp" numservices="10" services="21-23,25,80,110,139,443,445,3389"/>\n'
	nMap_Header += '<verbose level="0"/>\n'
	nMap_Header += '<debugging level="0"/>\n'

	mFile = open(mergeFile, "w")  
	mFile.write(nMap_Header) 
	mFile.close()

	for xml in xmlFiles:
		h = 0
		with open(mergeFile, mode = 'a', encoding='utf-8') as mergFile:
			with open(xml) as f:
				nMapXML = ET.parse(f)
				for host in nMapXML.findall('host'):
					h += 1
					cHost = ET.tostring(host, encoding='unicode', method='xml') 
					mergFile.write(cHost)
					mergFile.flush()
		os.remove(xml)	
		hosts_count += h

	# Add Footer to mergefile
	print('')
	print ("Output XML File:", os.path.abspath(mergeFile))
	nMap_Footer  = '<runstats><finished time="1" timestr="Wed Sep  0 00:00:00 0000" elapsed="0" summary="Nmap done at Wed Sep  0 00:00:00 0000; ' + str(hosts_count) + ' IP address scanned in 0.0 seconds" exit="success"/>\n'
	nMap_Footer += '</runstats>\n'
	nMap_Footer += '</nmaprun>\n'

	mFile = open(mergeFile, "a")  
	mFile.write(nMap_Footer) 
	mFile.close()

def subAquatone(program):
	print(tgood,"--- beginning aquatone enumeration of all new subdomains discovered for "+program,tend)

#	done = False

	#here is the animation
#	def animate():
#		for c in itertools.cycle(['*    ', '**   ', '***  ', '**** ', '*****', ' ****', '  ***', '   **', '    *', '   **', '  ***', ' ****', '*****', '**** ', '***  ', '**   ']):
#			if done:
#				break
#			sys.stdout.write('\r*** aquatoning '+program+' ' + c)
#			sys.stdout.flush()
#			time.sleep(0.1)
#
#	t = threading.Thread(target=animate)
#	t.daemon=True
#	if animation_on == 'true':
#		t.start()

	if aquatone_nmap == 'true':
		try:
			cat = subprocess.Popen(('cat', './programs/'+program+'/nmap_merged_'+timestamp+'.xml'), stdout=subprocess.PIPE)
			aqua = subprocess.call(('aquatone', '-nmap', '-out', './programs/'+program, '-http-timeout', aquatone_http_timeout), stdin=cat.stdout)
		except OSError as e:
			print (e.output)
	else:
		try:
			cat = subprocess.Popen(('cat', './programs/'+program+'/nmap_merged_'+timestamp+'.xml'), stdout=subprocess.PIPE)
			aqua = subprocess.call(('aquatone', '-ports', 'xlarge', '-out', './programs/'+program, '-http-timeout', aquatone_http_timeout), stdin=cat.stdout)
		except OSError as e:
			print (e.output)

	screendir = './programs/'+program+'/screenshots/'
	for f in os.listdir(screendir):
		os.chmod(os.path.join(screendir, f),0o744)


#	try:
#		shutil.rmtree(aquatone_web_path+'/'+program+'/aquatone_report.html')
#	except:
#		print(tnormal, aquatone_web_path+'/'+program+'/aquatone_report.html does not exist, no need to delete', tend)
#	try:
#		shutil.rmtree(aquatone_web_path+'/'+program+'/html')
#	except:
#		print(tnormal, aquatone_web_path+'/'+program+'/html does not exist, no need to delete', tend)
#	try:
#		shutil.rmtree(aquatone_web_path+'/'+program+'/headers')
#	except:
#		print(tnormal, aquatone_web_path+'/'+program+'/headers does not exist, no need to delete', tend)
#	try:
#		shutil.rmtree(aquatone_web_path+'/'+program+'/screenshots')
#	except:
#		print(tnormal, aquatone_web_path+'/'+program+'/screenshots does not exist, no need to delete', tend)
#	try:
#		os.makedirs(aquatone_web_path+'/'+program)
#	except:
#		print(tnormal,aquatone_web_path+'/'+program+' already exists, no need to create',tend)
#	shutil.move('./programs/'+program+'/aquatone_report.html', aquatone_web_path+'/'+program+'/aquatone_report.html')
#	shutil.move('./programs/'+program+'/screenshots', aquatone_web_path+'/'+program+'/')
#	shutil.move('./programs/'+program+'/html', aquatone_web_path+'/'+program+'/')
#	shutil.move('./programs/'+program+'/headers', aquatone_web_path+'/'+program+'/')

#	done = True

	print(tgood,"Latest aquatone results available in "+aquatone_web_path,tend)

	indexFile = aquatone_web_path+'/index.html'
	index_html = '<!DOCTYPE html>'
	index_html += '<html>'
	index_html += '<body>'
	index_html += '<h2>Existing aquatone results for all programs:</h2>'
	for f in os.listdir(aquatone_web_path):
		if not "index.html" in f and not ".DS_Store" in f:
			if not os.path.isdir(f):
				index_html += '<h4><a href="'+f+'/aquatone_report.html">'+f+'</a></br></h4>'
	index_html += '</body>'
	index_html += '</html>'

	iFile = open(indexFile, "w")  
	iFile.write(index_html) 
	iFile.close()			

def subReport(program):
	print(tnormal,"--- sending results email to " + receiver_email,tend)
	fp = open("programs/"+program+"/report.txt", "r")
	mail_content = fp.read()
	files = "programs/"+program
	filenames = [os.path.join(files, f) for f in os.listdir(files)]
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
				if re.search(r'\b'+program+r'\b', line):
					print(line)
					count+=1
			if count == 0:
				print(tbad,"Program with name '"+program+"' does not exist in programs.txt, add with './autofd add <program name>'\n",tend)
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
