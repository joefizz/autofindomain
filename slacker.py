#!/usr/bin/env python3

import requests, urllib, json, datetime, time as t

time = datetime.datetime.now()
keep = input('How many hours to keep? ')
oldest_time = time - datetime.timedelta(hours=int(keep))
oldest_epoch = int(oldest_time.timestamp())
print(oldest_epoch)

url=('https://slack.com/api/conversations.history?token=xoxb-262541194338-1293084920080-Z21cXgXdDdZDABIcrdG0D9OC&channel=C017XD809UK&latest='+str(oldest_epoch)+'.000000&pretty=1')
print(url)
r = requests.get(url)

data = r.json()

for (k,v) in data.items():
	#print('Key: '+str(k))
	#print('Value: '+str(v))
	if str(k) == 'messages':
		for message in v:
			for x in message:
				if x == 'ts':
					if float(message[x]) < oldest_epoch:
						print(message[x])
						data = {'token':'xoxb-262541194338-1293084920080-Z21cXgXdDdZDABIcrdG0D9OC','channel':'C017XD809UK','ts':message[x],'pretty':'1'}
						r = requests.post('https://slack.com/api/chat.delete', data)
						print(r.content)
						t.sleep(1)
