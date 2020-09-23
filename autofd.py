#!/usr/bin/env python3

import signal,  random, os, sys, glob, smtplib, ssl, string, configparser, urllib.request
import shutil, itertools, threading, time, platform, subprocess, re, stat, json, requests, socket
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
enable_email = parser['email']['enable_email'].lower()
port = parser['email']['port']
password = parser['email']['password']
sender_email = parser['email']['sender_email']
receiver_email = parser['email']['receiver_email']
email_server = parser['email']['email_server']
send_blank_emails = parser['email']['send_blank_emails'].lower()
send_attachments = parser['email']['send_attachments'].lower()
enable_programs_email = parser['email']['enable_programs_email'].lower()
enable_combined_email = parser['email']['enable_combined_email'].lower()

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
aquatone_url = parser['aquatone']['aquatone_url']
aquatone_new = parser['aquatone']['run_on_new_programs'].lower()
aquatone_nmap = parser['aquatone']['aquatone_nmap'].lower()
aquatone_http_timeout = parser['aquatone']['aquatone_http_timeout']
# Colour settings
colours = parser['colours']['colours'].lower()

# General settings
animation_on = parser['general']['animation_on'].lower()

# Slack settings
send_results_to_slack = parser['slack']['send_results_to_slack'].lower()
slack_channel = parser['slack']['slack_channel']
slack_oauth_token = parser['slack']['slack_oauth_token']

# FFuF settings
ffuf_on = parser['ffuf']['ffuf_on'].lower()
ffuf_on_new = parser['ffuf']['ffuf_on_new'].lower()

# nuclei settings
nuclei_on = parser['nuclei']['nuclei_on'].lower()
nuclei_on_new = parser['nuclei']['nuclei_on_new'].lower()

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

def subEnumerate(program):
	start = datetime.now()
	print(tnormal, str(start) + " - Beginning subdomain search of domains in " + program , tend)
	sources()
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
		else:
			print(tnormal,'--- Searching subdomains of %s'%(domain),tend)

		try:
			os.system('./links/amass enum -config ./amass_config.ini -exclude "Brute Forcing" -w /opt/autofindomain/amass/dns.txt -d '+domain+' -noalts -o out.txt -min-for-recursive 2 -rf ./dns_resolvers.txt')
		except Exception as e:
			print(e)



		try:
			os.system("sort -u out.txt > "+path+"_latest-"+timestamp+".txt")
			os.system("rm out.txt")
		except Exception as e:
			print(e)
		done = True
		end = datetime.now()
		runtime = end-start
		print(tgood, str(end)+" - Latest subdomain results available in "+path+"_latest.txt",tend)
		print(tnormal, '--- runtime: '+str(runtime))

def subTrack(program):
	start = datetime.now()
	print(tnormal, str(start)+' - beginning tracking of results for '+program, tend)
	global new_program
	new_domain_count = 0
	new_domain_total = 0
	os.system("echo "+program+"> programs/"+program+"/report.txt")
	f = open("programs/" + program + "/domains.txt")
	for domain in f:
		domain = domain.rstrip('\n')
		path="programs/"+program+"/"+domain
		print(tnormal,"\n--- Comparing new discoveries to existing discoveries for "+domain,tend)
		if os.path.isfile(path+"_all.txt") == False:
			print("First enum for this domain, no results to compare")
			os.system("cp "+path+"_latest-"+timestamp+".txt "+path+"_all.txt")
			print("Subdomains saved to "+path+"_all.txt")
			os.system("cp "+path+"_latest-"+timestamp+".txt "+path+"_new-"+timestamp+".txt")
			new_domain_total = sum(1 for line in open(path+"_new-"+timestamp+".txt"))
			new_program = 1
		else:
			os.system("comm -23 "+path+"_latest-"+timestamp+".txt "+path+"_all.txt > "+path+"_new-"+timestamp+".txt")
			new_domain_count = sum(1 for line in open(path+"_new-"+timestamp+".txt"))
			if new_domain_count > 0:
				os.system("cp "+path+"_new-"+timestamp+".txt "+path+"_new.txt")
				print(tgood,"--- "+str(new_domain_count)+" new subdomains for "+domain+" saved to "+path+"_new.txt",tend)
			new_domain_total += new_domain_count
			os.system("cp "+path+"_all.txt "+path+"_temp.txt")
			os.system("cat "+path+"_new-"+timestamp+".txt >> "+path+"_temp.txt")
			os.system("sort -u "+path+"_temp.txt > "+path+"_all.txt")
		print(tgood,"Newly discovered subdomains (if any) added to all",tend)
		try:
			shutil.move(path+"_latest-"+timestamp+".txt", path+"_latest.txt")
		except Exception as e:
			print(e)
	os.system("cat programs/"+program+"/*_new-"+timestamp+".txt >> programs/"+program+"/report.txt")
	if new_domain_count > 0:
		 os.system("cat programs/"+program+"/report.txt >> ./report_subdomains-"+timestamp+".txt")
	end = datetime.now()
	runtime = end-start
	print(tgood, str(end)+' - tracking completed - runtime: '+str(runtime), tend)

	return new_domain_total

def subNmap(program):

	print(tnormal,"--- Removing historic nmap files from "+program+" folder.",tend)
	dir = "./programs/"+program
	for f in os.listdir(dir):
		if re.search('nmap', f):
			print("    deleting: "+f)
			os.remove(os.path.join(dir, f))	
	start = datetime.now()

	print(tnormal,str(start)+" - Beginning NMAP scans of all new subdomains discovered for "+program,tend)
	f = open("programs/" + program + "/domains.txt")
	port_count = 0
	for domain in f:
		newSubdomains = []
		domain = domain.rstrip('\n')
		path="programs/"+program+"/"+domain
		try:
			s = open(path+"_new-"+timestamp+".txt")
		except Exception as e:
			print(e)
			continue
		for subdomain in s:
			subdomain=subdomain.rstrip('\n')
			if testSubdomain(subdomain):
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
				proc = subprocess.call(['nmap','-n','--open','-p','80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4080,4243,4443,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017']+nmap_args, stdout=FNULL, stderr=subprocess.STDOUT)
			except OSError as e:
				print (e.output)
			shutil.move('programs/'+program+'/'+subdomain+'_nmap_'+timestamp+'.nmap', path+'_nmap_'+timestamp+'.txt')
			file = open('programs/'+program+'/'+subdomain+'_nmap_'+timestamp+'.gnmap', "r")
			for line in file:
				line = line.lower()
				if re.search('open', line):
					port_count += 1
			done = True

			print(tgood,'Latest nmap results available in programs/'+program+'/'+subdomain+'_nmap_'+timestamp+'.{txt,gnmap,xml}',tend)
	xmlFiles = []

	dir = "./programs/"+program
	for f in os.listdir(dir):
		if f.lower().endswith('_nmap_'+timestamp+'.xml'):
			xmlFiles.append(os.path.join(dir, f))
	if xmlFiles:
		xmlMerge(xmlFiles, program)
	end = datetime.now()
	runtime = end-start

	print(tnormal, '--- runtime: '+str(runtime))

	return port_count

def xmlMerge(xmlFiles, program):

	hosts_count = 0

	# Check to ensure we have work to do
	if not xmlFiles:
		print("No XML files were found ... No work to do")
		return

	# Create the Merged filename
	path="programs/"+program

	mergeFile = path+"/nmap_merged_" + timestamp + ".xml"

	# Add Header to mergefile
	nMap_Header  = '<?xml version="1.0" encoding="UTF-8"?>\n'
	nMap_Header += '<!DOCTYPE nmaprun>\n'
	nMap_Header += '<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n'
	nMap_Header += '<nmaprun scanner="nmap" args="check config.ini" start="123" startstr="Fri Jul  3 15:42:58 2020" version="7.80" xmloutputversion="1.04">\n'
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
	start = datetime.now()

	screenshots = 0
	print(tgood, str(start) +" - beginning aquatone enumeration of all new subdomains discovered for "+program,tend)

	if aquatone_nmap == 'true':
		try:
			cat = subprocess.Popen(('cat', './programs/'+program+'/nmap_merged_'+timestamp+'.xml'), stdout=subprocess.PIPE)
			aqua = subprocess.call(('aquatone', '-nmap', '-out', './programs/'+program, '-http-timeout', aquatone_http_timeout), stdin=cat.stdout)
		except OSError as e:
			print (e.output)
	else:
		try:
			cat = subprocess.Popen(('cat', './programs/'+program+'/report.txt'), stdout=subprocess.PIPE)
			aqua = subprocess.call(('aquatone', '-out', './programs/'+program, '-ports', 'xlarge', '-http-timeout', aquatone_http_timeout), stdin=cat.stdout)
		except OSError as e:
			print (e.output)

	screendir = './programs/'+program+'/screenshots/'
	for f in os.listdir(screendir):
		screenshots += 1
		os.chmod(os.path.join(screendir, f),0o744)


	try:
		shutil.rmtree(aquatone_web_path+'/'+program+'/aquatone_report.html')
	except:
		print(tnormal, aquatone_web_path+'/'+program+'/aquatone_report.html does not exist, no need to delete', tend)
	try:
		shutil.rmtree(aquatone_web_path+'/'+program+'/html')
	except:
		print(tnormal, aquatone_web_path+'/'+program+'/html does not exist, no need to delete', tend)
	try:
		shutil.rmtree(aquatone_web_path+'/'+program+'/headers')
	except:
		print(tnormal, aquatone_web_path+'/'+program+'/headers does not exist, no need to delete', tend)
	try:
		shutil.rmtree(aquatone_web_path+'/'+program+'/screenshots')
	except:
		print(tnormal, aquatone_web_path+'/'+program+'/screenshots does not exist, no need to delete', tend)
	try:
		os.makedirs(aquatone_web_path+'/'+program)
	except:
		print(tnormal,aquatone_web_path+'/'+program+' already exists, no need to create',tend)
	try:
		shutil.move('./programs/'+program+'/aquatone_report.html', aquatone_web_path+'/'+program+'/aquatone_report.html')
	except Exception as e:
		print(e)
	try:
		shutil.move('./programs/'+program+'/screenshots', aquatone_web_path+'/'+program+'/')
	except Exception as e:
		print(e)	
	try:
		shutil.move('./programs/'+program+'/html', aquatone_web_path+'/'+program+'/')
	except Exception as e:
		print(e)
	try:
		shutil.move('./programs/'+program+'/headers', aquatone_web_path+'/'+program+'/')
	except Exception as e:
		print(e)

	print(tgood,"Latest aquatone results available in "+aquatone_web_path,tend)

	indexFile = aquatone_web_path+'/index.html'
	index_html = '<!DOCTYPE html>'
	index_html += '<html>'
	index_html += '<body>'
	index_html += '<h2>Existing aquatone results for all programs:</h2>'
	paths = sorted(Path(aquatone_web_path).iterdir(), key=os.path.getmtime, reverse=True)

	for p in paths:
		pname = p.name
		if not "index.html" in pname and not ".DS_Store" in pname:
			if not os.path.isdir(pname):
				index_html += '<h4><a href="'+pname+'/aquatone_report.html">'+pname+'</a></br></h4>'
	index_html += '</body>'
	index_html += '</html>'

	iFile = open(indexFile, "w")  
	iFile.write(index_html) 
	iFile.close()			
	end = datetime.now()
	runtime = end-start
	print(tnormal, str(end)+' - Aquatone finished. runtime: '+str(runtime))

	return screenshots

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
		try:
			server.sendmail(sender_email, receiver_email.split(','), msg.as_string())
		except Exception as e:
			print(e)

def report():
	print(tnormal,"--- sending combined subdomain report email to " + receiver_email,tend)
	fp = open("./report_subdomains-"+timestamp+".txt", "r")
	mail_content = fp.read()
	msg = MIMEMultipart()
	msg['Subject'] = "findomain combined subdomain report"
	msg['From'] = sender_email
	msg['To'] = receiver_email
	msg.attach(MIMEText(mail_content, 'plain'))
	context = ssl.create_default_context()
	with smtplib.SMTP_SSL(email_server, port, context=context) as server:
		server.login(sender_email, password)
		try:
			server.sendmail(sender_email, receiver_email.split(','), msg.as_string())
		except Exception as e:
			print(e)

	print(tnormal,"--- sending combined nuclei report email to " + receiver_email,tend)
	fp = open("./report_nuclei-"+timestamp+".txt", "r")
	mail_content = fp.read()
	msg = MIMEMultipart()
	msg['Subject'] = "findomain combined nuclei report"
	msg['From'] = sender_email
	msg['To'] = receiver_email
	msg.attach(MIMEText(mail_content, 'plain'))
	context = ssl.create_default_context()
	with smtplib.SMTP_SSL(email_server, port, context=context) as server:
		server.login(sender_email, password)
		try:
			server.sendmail(sender_email, receiver_email.split(','), msg.as_string())
		except Exception as e:
			print(e)

def dirsearch(program):
	print (tgood,"Beginning directory search for new subdomains in %s"%(program),tend)
	f = open('./programs/'+program+'/aquatone_session.json')
	data = json.load(f)
	f.close()

	for (k,v) in data.items():
		if k == 'pages':
			for key in v:
				url = v[key]['url']
				hostname = v[key]['hostname']
				fuzzname = url+'FUZZ'
				if 'https' in url:
					hostname = 'https-'+hostname
				print (tgood,"--- Beginning directory search on %s"%(url),tend)

				try:
					os.system('./links/ffuf -maxtime 120 -s -o ./programs/'+program+'/'+hostname+'-ffuf_out-'+timestamp+'.json -timeout 5 -u '+ fuzzname+ ' -w ./ffuf/dict.txt -D -e php,txt,html -ic -ac -fc 403')
				except OSError as e:
					print (e.output)

def nuclei(program):
	print (tgood,"Beginning nuclei scan for new subdomains in %s"%(program),tend)
	f = open('./programs/'+program+'/aquatone_session.json')
	data = json.load(f)
	f.close()
	hosts = set()
	os.system('echo '+program+' > ./programs/'+program+'/nuclei-out-'+timestamp+'.txt')
	for (k,v) in data.items():
		if k == 'pages':
			for key in v:
				url = v[key]['url']
				hostname = v[key]['hostname']
				if 'https' in url:
					hostname = 'https-'+hostname
				hosts.add(url)
	print(hosts)
	with open('./programs/'+program+'/urls-'+timestamp+'.txt', 'w') as u:
		for item in hosts:
			u.write("%s\n" % item)
	nuclei_args = ' -silent -t technologies/ -t vulnerabilities/ -t default-credentials/ -t subdomain-takeover/ -t cves/ -t files/ -t security-misconfigurations/ -t tokens/ -t dns/ -t generic-detection/ -t vulnerabilities/ -t workflows/'
	os.system('./links/nuclei -update-directory ./nuclei/ -update-templates')
	os.system('cat ./programs/'+program+'/urls-'+timestamp+'.txt | ./links/nuclei '+nuclei_args+' -o ./programs/'+program+'/nuclei-out-'+timestamp+'.txt')

	lines = 0
	try:
		file = open('./programs/'+program+'/nuclei-out-'+timestamp+'.txt', 'r')
	except Exception as e:
		print(e)
	else:
		for line in file:
			line = line.strip('\n')
			lines+=1
		file.close()
	if lines > 1:
		os.system('cat ./programs/'+program+'/nuclei-out-'+timestamp+'.txt >> ./report_nuclei-'+timestamp+'.txt')
		lines = 0

def toSlack(program):
	print (tgood,"Sending latest data for %s to slack"%(program),tend)
	slack_api = 'https://slack.com/api/'
	f = open('./programs/'+program+'/aquatone_session.json')
	data = json.load(f)
	f.close()
	for (k,v) in data.items():
		if k == 'pages':
			for key in v:
				results_list = '- FFuF Results:\n'
				ports_list = '\n- open ports:\n'
				nuclei_results = '\n- nuclei results:\n'
				url = v[key]['url']
				hostname = v[key]['hostname']
				screenshotPath = v[key]['screenshotPath']
				IP = v[key]['addrs']
				status = v[key]['status']
				headerfile = v[key]['headersPath']
				header = open(aquatone_web_path+'/'+program+'/'+headerfile)
				htext = header.read()
				header.close()
				proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
				tree = ET.parse('./programs/'+program+'/'+hostname+'_nmap_'+timestamp+'.xml')
				root = tree.getroot()
				for port in root.iter('port'):
					ports_list += '    '+str(port.attrib['protocol']+' : '+port.attrib['portid'] + '\n')

				if 'https' in url:
					hostname = 'https-'+hostname

				try:
					f = open('./programs/'+program+'/'+hostname+'-ffuf_out-'+timestamp+'.json')
					ffufdata = json.load(f)
					f.close()
				except Exception as e:
					print(e)
				else:
					for (k1,v1) in ffufdata.items():
						if k1 == 'results':
							results = v1
					for r in results:
						results_list += str(r['status'])+' - '+r['url']+'\n'

				try:
					data = {'initial_comment':'New subdomain discovered for '+program+': '+url+'\n - with status '+str(status)+'\n - pointing to '+str(IP)+ports_list+'\n- full aquatone results: '+aquatone_url+'/'+program+'/aquatone_report.html\n'+'```'+htext+'```\n'+results_list,'channels':slack_channel}
				except Exception as e:
					print(e)
				headers = {'Authorization':'Bearer '+slack_oauth_token}
				if screenshotPath == "":
					try:
						r = requests.post(slack_api+'chat.postMessage', {'message':'New subdomain without screenshot discovered for '+program+': '+url+' - pointing to '+str(IP),'channels':slack_channel}, headers=headers,)
					except Exception as e:
						print(tbad,e,tend)
				else:	
					try:
						r = requests.post(slack_api+'files.upload', data, headers=headers, files={"file": (aquatone_web_path+'/'+program+'/'+screenshotPath, open(aquatone_web_path+'/'+program+'/'+screenshotPath, "rb"), "image/png")})
					except Exception as e:
						print(tbad,e,tend)

	nuclei_results = '\n'
	try:
		with open('./programs/'+program+'/nuclei-out-'+timestamp+'.txt', 'r') as file:
			nuclei_results += file.read()
	except Exception as e:
		print(e)

	headers = {'Authorization':'Bearer '+slack_oauth_token}
	try:
		r = requests.post(slack_api+'chat.postMessage', {'text':'Nuclei results for '+program+nuclei_results,'channel':slack_channel}, headers=headers,)
	except Exception as e:
			print(tbad,e,tend)

def testSubdomain(subdomain):

	d = open('./excludedomains.txt', 'r')
	dlist = d.readlines()
	d.close()
	for d in dlist:
		d = d.strip('\n')
		if d in subdomain:
			print('%s contains %s which is in excludedomains.txt'%(subdomain,d))
			return False
	if subdomain.count('.') == 1:
		print('This appears to be a root domain and therefore likely not a wildcard response - %s'%(subdomain))
		return True
	if subdomain.count('.') == 2:
		print('This appears to be attached to the root domain and therefore likely not a wildcard response - %s'%(subdomain))
		return True
	testdomain = get_random_string(12)+'.'+ subdomain.split('.',1)[1]
	try:
		ip = socket.gethostbyname(testdomain)
	except Exception as e:
		print(tgood,'No IP resolution for %s, %s likely valid domain.'%(testdomain, subdomain),tend)
		return True
	else:
		print(tbad,'Received IP resolution for %s pointing to %s. %s likely wildcard response'%(testdomain,ip,subdomain),tend)
		return False

def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    #print("Random string of length", length, "is:", result_str)
    return result_str

def folder_clean(program):
	flist = glob.glob('./programs/'+program+'/*'+timestamp+'*')
	for f in flist:
		try:
			os.remove(f)
		except:
			print(tbad, "Error while deleting file : ", f, tend)
			
def ctrlc(sig, frame):
	c = input('Ctrl-c detected, would you like to (e)nd or (c)ontinue?').lower()
	if c == 'e':
		fin(1)
	signal.signal(signal.SIGINT, original_sigint)

	try:
		if raw_input("\nCtrl-c detected, would you like to (e)nd or (c)ontinue?: ").lower().startswith('e'):
			sys.exit(1)

	except KeyboardInterrupt:
		print("Ok ok, quitting")
		fin(1)

    # restore the exit gracefully handler here    
	signal.signal(signal.SIGINT, ctrlc)

def fin(status):
	flist = glob.glob('./report*')
	for f in flist:
		try:
			os.remove(f)
		except:
			print(tbad, "Error while deleting file : ", f, tend)
	total_runtime = datetime.now()-now
	print(tgood,'\n---- autoFD complete.  Total running time: '+str(total_runtime)+'\n')
	os.remove('/tmp/autofd.pid')

	sys.exit(status)

def bins(linux):
	linux == linux
	if linux == 'true':
		os.system('ln -s `pwd`/amass/linux/amass ./links/amass')
		os.system('ln -s `pwd`/ffuf/linux/ffuf ./links/ffuf')
		os.system('ln -s `pwd`/nuclei/linux/nuclei ./links/nuclei')
		os.system('ln -s `pwd`/subfinder/linux/subfinder ./links/subfinder')
	else:
		os.system('ln -s `pwd`/amass/mac/amass ./links/amass')
		os.system('ln -s `pwd`/ffuf/mac/ffuf ./links/ffuf')
		os.system('ln -s `pwd`/nuclei/mac/nuclei ./links/nuclei')
		os.system('ln -s `pwd`/subfinder/mac/subfinder ./links/subfinder')

def sources():
	with urllib.request.urlopen("https://public-dns.info/nameserver/gb.json") as url:
		data = json.loads(url.read().decode())
	sources = ""
	for source in data:
		if source["reliability"] > 0.99:
			sources += source["ip"]+'\n'
	f = open("./dns_resolvers.txt", "w")
	f.writelines(sources)
	f.close()

def main():

	global new_program
	total_subdomains = 0
	original_sigint = signal.getsignal(signal.SIGINT)
	signal.signal(signal.SIGINT, ctrlc)
	if os.path.isfile('/tmp/autofd.pid'):
		print(tbad,'/tmp/autofd.pid detected indicating autofd already running')
		sys.exit(1)

	os.system('touch /tmp/autofd.pid')

	if sys.version_info <= (3, 0):
		print(tbad,"This script requires Python 3.4+\n",tend)
		fin(1)

	if nmap_on == 'true':
		try:
			FNULL = open(os.devnull, 'w')
			proc = subprocess.call(['nmap','--version'],stdout=FNULL, stderr=subprocess.STDOUT)
		except OSError as e:
			print (tbad,'*** Nmap is not installed in path, install nmap to path or disable port scanning in config.ini\n',tend)
			fin(1)

	if aquatone_on == 'true':
		try:
			FNULL = open(os.devnull, 'w')
			proc = subprocess.call(['aquatone','-version'],stdout=FNULL, stderr=subprocess.STDOUT)
		except OSError as e:
			print (tbad,'*** Aquatone is not installed in path, install nmap to path or disable port scanning in config.ini\n',tend)
			fin(1)
		
		try:
			FNULL = open(os.devnull, 'w')
			proc = subprocess.call(['ls',aquatone_web_path],stdout=FNULL, stderr=subprocess.STDOUT)
		except OSError as e:
			print (tbad,'*** Aquatone HTML output folder does not exist.  Check aquatone_web_path in config.ini\n',tend)
			fin(1)


	if platform.system() == "Linux":
		linux = "true"

	elif platform.system() == "Darwin":
		linux = "false"
	else:
		print(tbad,"AutoFD currently only works on mac and Linux.",tend)
		fin(1)

	if len(sys.argv) < 2:
		print(tgood+"autofd usage\n\n./autofd.py <option>\n\nOptions: enum, add, del, list, email, purge\n",tend)
		fin(1)

	bins(linux)

	if (sys.argv[1]).lower() == "enum" or (sys.argv[1]).lower() == "program":
		
		if platform.system() == "Linux":
			if os.geteuid() != 0:
				print(talert,"*** autoFD on Linux requires running as sudo.  \nThis is to improve nmap scan speed, but more importantly to ensure permissions for various things work.",tend)
				if not input("\n  Enter YES to continue without sudo and watch the world burn: ").lower() == 'yes':
					fin(1)
		if os.path.isfile(programs) == False:
			print(tbad,"No programs to enumerate.  Have you run `./autofindomain.py add`  ?",tend)
			fin(1)
		if linux == "true":
			print(tnormal,"--- Downloading latest version of findomain",tend)
			if os.path.isfile("./findomain"):
				os.system("rm -f ./findomain")
			os.system("wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux -q --show-progress; mv findomain-linux findomain; chmod +x findomain")
		p = open(programs)

		if (sys.argv[1]).lower() == "enum":
			aquatone = False
			for program in p:
				exclude = False
				try:
					ex = open('./exclude.txt','r')
					exlist = ex.readlines()
					ex.close()
				except Exception as e:
					print(e)
				else:
					for line in exlist:
						if line.rstrip('\n') == program.rstrip('\n'):
							print(tbad,'**** Program %s is in exclude list, skipping'%(program.rstrip('\n')),tend)
							exclude = True
				if exclude:
					continue
				screenshots = 0
				program = program.rstrip('\n')
				print("\n\n*** Program = " + program)
				if sum(1 for line in open('./programs/'+program+'/domains.txt')) < 1:
					print(tbad, '*** Program %s does not have any domains.  Add them to domains.txt or use:\n\n    ./autofd.py add-domain <program> <domain>'%(program),tend)
					continue
				subEnumerate(program)
				new_domains = subTrack(program)
				print("--- New subdomains: "+str(new_domains))
				total_subdomains += new_domains
				port_count = 0
				if nmap_on == 'true' and new_domains > 0:
					if new_program == 0 or nmap_new == 'true':
						port_count = subNmap(program)

					if aquatone_on == 'true' and port_count > 0:
						if new_program == 0 or aquatone_new == 'true':
							aquatone = True
							screenshots = subAquatone(program)
						if ffuf_on == 'true':
							if new_program == 0 or ffuf_on_new == 'true':
								dirsearch(program)
						if nuclei_on == 'true':
							if new_program == 0 or nuclei_on_new == 'true':
								nuclei(program)

				if enable_email == 'true':
					if enable_programs_email == 'true':
						if send_blank_emails == 'true' or new_domains > 0:
							subReport(program)

				if send_results_to_slack == 'true' and new_domains > 0 and new_program == 0 and screenshots > 0:
					toSlack(program)
				folder_clean(program)
				
				new_program = 0

			print(tgood,'--- Total new subdomains discovered during enumeration: '+str(total_subdomains))
			if enable_email == 'true':
				if enable_combined_email == 'true':
					if send_blank_emails == 'true' or total_subdomains > 0:
						report()


		elif (sys.argv[1]).lower() == "program":
			aquatone = False
			screenshots = 0
			program = sys.argv[2].rstrip('\n')

			file = open(programs, "r")
			count = 0
			for line in file:
				if re.search(r'\b'+program+r'\b', line):
					print(line)
					count+=1
			if count == 0:
				print(tbad,"Program with name '"+program+"' does not exist in programs.txt, add with './autofd add <program name>'\n",tend)
				fin(1)

			print("\n\n *** Program = " + program)
			if sum(1 for line in open('./programs/'+program+'/domains.txt')) < 1:
					print(tbad, '*** Program %s does not have any domains.  Add them to domains.txt or use:\n\n    ./autofd.py add-domain <program> <domain>'%(program),tend)
					fin(1)
			subEnumerate(program)
			new_domains = subTrack(program)
			print("--- send_blank_emails: "+send_blank_emails)
			print("--- new_subdomains: "+str(new_domains))
			port_count = 0
			if nmap_on == 'true' and new_domains > 0:
				print('*** new_program = '+str(new_program))
				if new_program == 0 or nmap_new == 'true':
					port_count = subNmap(program)
				if aquatone_on == 'true' and port_count > 0:
					if new_program == 0 or aquatone_new == 'true':
						aquatone = True
						screenshots = subAquatone(program)
					if ffuf_on == 'true':
						if new_program == 0 or ffuf_on_new == 'true':
							dirsearch(program)
					if nuclei_on == 'true':
							if new_program == 0 or nuclei_on_new == 'true':
								nuclei(program)
			if enable_email == 'true':
				if enable_programs_email == 'true':
					if send_blank_emails == 'true' or new_domains > 0:
						subReport(program)
				if enable_combined_email == 'true':
					if send_blank_emails == 'true' or new_domains > 0:
						report()
			if send_results_to_slack == 'true' and new_domains > 0 and new_program == 0 and screenshots > 0:
				toSlack(program)
			folder_clean(program)

		fin(1)

	if (sys.argv[1]) == "slack":
		program = sys.argv[2].rstrip('\n')
		print(tnormal,"Sending latest data for %s to slack"%(program),tend)
		p = open(programs)
		for line in p:
			line = line.rstrip('\n')
			if line == program:
				print("Program " + program +" exists")
				toSlack(program)
				fin(1)
		p.close()


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
				fin(1)
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
		fin(1)

	if (sys.argv[1]) == "add-domain":
		if len(sys.argv) < 4:
			print(tnormal,'./autofd.py add-domain <program> <domain> <domain> <domain> ...')
			fin(1)
		program = sys.argv[2].rstrip('\n')
		domain = sys.argv[3].rstrip('\n')
		p = open(programs)
		for prog in p:
			prog = prog.rstrip('\n')
			if prog == program:

				dw = open('./programs/'+program+'/domains.txt', 'a')
				dr = open('./programs/'+program+'/domains.txt', 'r')
				drlist = dr.readlines()
				dr.close
				for i in sys.argv[3:]:
					found = False
					for line in drlist:
						line = line.rstrip('\n')
						if line == i:
							print(tnormal,'--- Domain %s already in program'%(i),tend)
							found = True
					if not found:
						print(tgood,'--- Adding %s to domains.txt for program %s'%(i,program),tend)
						dw.write(i+'\n')
						found = False
				dw.close()
				with open('./programs/'+program+'/domains.txt') as temp_file:
  					drugs = [line.rstrip('\n') for line in temp_file]
				d = open('./programs/'+program+'/domains.txt')
				print(tgood,'\nDomains for program: '+program,tend)
				for line in d:
					line = line.rstrip('\n')
					print(line)
				d.close()
				fin(1)
		print(tbad,'Program [%s] does not exist. use \'./autofd list\' to show existing programs'%(program),tend)

	if sys.argv[1] == "del":
		if os.path.isfile(programs) == False:
			print("No programs to delete")
			fin(1)
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
		fin(1)

	if sys.argv[1] == "list":
		pcount = 0
		dcount = 0
		if os.path.isfile(programs) == False:
			print("No programs to list.  add with add")
			fin(1)
		print(tnormal,"Current programs that will be enumerated:",tend)
		p = open(programs)
		for program in p:
			pcount += 1
			program = program.rstrip('\n')
			print("\n"+program)
			f = open("./programs/"+program+"/domains.txt")
			for domain in f:
				dcount += 1
				print("    "+domain.rstrip('\n'))
		print(tgood,'\n ---- Total programs: %s'%(str(pcount)),tend)
		print(tgood,'---- Total domains across all programs: %s'%(str(dcount)),tend)
		fin(1)

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

	os.remove('/tmp/autofd.pid')

if __name__ == "__main__":
	original_sigint = signal.getsignal(signal.SIGINT)
	signal.signal(signal.SIGINT, ctrlc)
	main()
