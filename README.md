# autoFD

				              __         _______ ______   
				 .---.-.--.--|  |_.-----|   _   |   _  \  
				 |  _  |  |  |   _|  _  |.  1___|.  |   \ 
				 |___._|_____|____|_____|.  __) |.  |    \
				                        |:  |   |:  1    /
				                        |::.|   |::.. . / 
				                        `---'   `------'  
				                                          

Usage is pretty basic.  Currently it works for Mac OS and Linux (make sure to set this in the config.ini file)

For Linux there are no pre-reqs (I think)

For Mac OS you need to have findomain already installed - `brew install findomain` - done

## Setup steps:
Create Gmail account and enable insecure applications (https://myaccount.google.com/lesssecureapps).

`cp config.ini.default config.ini` and update required settings.

To automate this via cron use a cron entry similar to: 

```
0 0 * * * cd /opt/autofindomain && /opt/autofindomain/autofd.py enum > /opt/autofindomain/log_`date +\%d-\%m-\%y:\%H-\%M`.txt
```

This will have it run every midnight and create a log file for each run. (These can get quite large and will need a manual cleanup)

## Features:

`enum` - downloads latest findomain(linux only) and enumerates all the root domains stored with programs. tracks the changes and sends email alerting to all subdomain changes.

`add` - adds a new program to the enumeration task. list of programs is stored in programs.txt. findomain data for programs is stored separately for each one in the ./programs/ folder. Once a programs is added the root domains should be added to the domains.txt file in the programs folder.

`delete` - deletes a program from the programs.txt file but leaves the program folder intact.

`list` - list all existing programs and associated root domains currently configured.

`purge` - deletes folders for all programs that are NOT in the programs.txt file.

`program <program_name>` - run against just one program from programs.txt rather than all of them.  Will error out if the program doesn't already exist.

Example:
```
./autofd.py add verizon
echo verizon.com > ./programs/verizon/domains.txt
./autofd.py enum
```