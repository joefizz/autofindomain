#!/usr/bin/env python3

import requests, socket, random, string, os, subprocess

twhite = '\033[40m'
tgood = '\033[32m'
tnormal = '\033[33m'
tbad = '\033[31m'
talert = '\033[31m'
tend = '\033[m'

def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    #print("Random string of length", length, "is:", result_str)
    return result_str

url = 'https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/master/chaos-bugbounty-list.json'

r = requests.get(url)

data = r.json()

programs_to_add_count = 0
domains_to_add_count = 0

pr = open ('./programs.txt', 'r')
plist = pr.readlines()
pr.close()

for (k,v) in data.items():
	for program in v:
		found = False
		program_name = program['name'].replace(" ","_").replace("(","").replace(")","").replace("&","and").replace("'","").replace("!","").lower()
		print(tgood,'\n---- Program: '+program_name,tend)
		for line in plist:
			line = line.rstrip('\n')
			if line == program_name:
				print(tnormal,'--- Program %s already in autofd'%(line),tend)
				found = True
				print('found: '+str(found))
		if not found:
			print(tgood,'--- Adding %s to autofd'%(program_name),tend)
			try:
				FNULL = open(os.devnull, 'w')
				proc = subprocess.call(['./autofd.py', 'add', program_name],stdout=FNULL, stderr=subprocess.STDOUT)
			except OSError as e:
				print (e.output)
			found = False



		valid_domains=0
		domains_to_add=[]

		domains = program['domains']
		for domain in domains:
			print('Domain: '+domain)
			testdomain = get_random_string(12)+'.'+domain
			print(tnormal,'Testing for wildcard domain using: %s'%(testdomain),tend)
			try:
				ip = socket.gethostbyname(testdomain)
			except Exception as e:
				print(tgood,'No IP resolution for %s, %s will be added to autofd'%(testdomain, domain),tend)
				domains_to_add.append(domain)
				valid_domains += 1

			else:
				print(tbad,'Received IP resolution for %s pointing to %s. %s will not be added to autofd'%(testdomain,ip,domain),tend)
		if valid_domains > 0:
			dr = open('./programs/'+program_name+'/domains.txt')
			dlist = dr.readlines()
			dr.close()

			for domain in domains_to_add:

				for line in dlist:
					line = line.rstrip('\n')
					if line == domain:
						print(tnormal,'--- Domain %s already in program %s'%(domain,program_name),tend)
						found = True
				if not found:
					print(tgood,'--- Adding %s to program %s'%(domain,program_name),tend)
					try:
						FNULL = open(os.devnull, 'w')
						proc = subprocess.call(['./autofd.py', 'add-domain', program_name, domain],stdout=FNULL, stderr=subprocess.STDOUT)
					except OSError as e:
						print (e.output)
					found = False


			programs_to_add_count += 1
		else:
			print(tbad,'Will not add this program to autofd',tend)
		domains_to_add_count += valid_domains

print(tgood,'Adding %s new programs to autofd with a total of %s domain'%(str(programs_to_add_count),str(domains_to_add_count)),tend)
				

		#print(program['domains'])
		#program = v[key]['name']
		#print(type(program))
		#print(program)