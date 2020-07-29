#!/usr/bin/env python3

import requests, socket, random, string

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

for (k,v) in data.items():
	for program in v:
		valid_domains=0
		domains_to_add=[]
		print('\nProgram: '+program['name'])
		domains = program['domains']
		for domain in domains:
			print('Domain: '+domain)
			testdomain = get_random_string(12)+'.'+domain
			print(tnormal,'Testing for wildcard domain using: %s'%(testdomain),tend)
			try:
				ip = socket.gethostbyname(testdomain)
			except Exception as e:
				print(tgood,'No wildcard response for %s, will be added to autofd'%(testdomain),tend)
				domains_to_add.append(domain)
				valid_domains += 1

			else:
				print(tbad,'Received wildcard response for %s pointing to %s. %s will not be added to autofd'%(testdomain,ip,domain),tend)
		if valid_domains > 0:
			print(tnormal,'Adding these domains to autofd:',tend)
			for domain in domains_to_add:
				print(tgood,domain,tend)
			programs_to_add_count += 1
		else:
			print(tbad,'Will not add this program to autofd',tend)
		domains_to_add_count += valid_domains

print(tgood,'Adding %s new programs to autofd with a total of %s domain'%(str(programs_to_add_count),str(domains_to_add_count)),tend)
				

		#print(program['domains'])
		#program = v[key]['name']
		#print(type(program))
		#print(program)