# pfloggerd

pf log daemon for macOS

pf is the built-in macOS packet filter, pfloggerd is a tool used to save pf logs to file in a human readable format.
pfloggerd reads pf logs from pflog0 interface and saves it to /var/log/pffirewall.log.
pfloggerd is part of Murus, a pf GUI front end for macOS. More info at www.murusfirewall.com 

pfloggerd needs to be launched by root at system boot using a shell script that:
- creates the pflog0 interface needed by pf
- runs pfloggerd

For that purpose we provide an example boot script, it.murus.pfloggerd.plist.
Copy this file to /Library/LaunchDaemons/ , set its ownership to root:wheel and permission to 644. Then copy pfloggerd binary to /usr/local/bin/ . Reboot your Mac to start pfloggerd.
