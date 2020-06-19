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

cp config.ini.default config.ini and update required settings.

## Features:

`enum` - downloads latest findomain(linux only) and enumerates all the root domains stored with programs. tracks the changes and sends email alerting to all subdomain changes.

`add` - adds a new program to the enumeration task. list of programs is stored in programs.txt. findomain data for programs is stored separately for each one in the ./programs/ folder. Once a programs is added the root domains should be added to the domains.txt file in the programs folder.

`delete` - deletes a program from the programs.txt file but leaves the program folder intact.

`purge` - deletes folders for all programs that are NOT in the programs.txt file.

`dns` - updates the list of DNS resolvers used by amass.

Example:
```
./autofd.py dns
./autofd.py add verizon
echo verizon.com > ./programs/verizon/domains.txt
./autofd.py enum
```