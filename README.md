# pfloggerd

pf log daemon for macOS

pfloggerd is used to read pf (packet filter) logs from pflog0 interface and save it to /var/log/pffirewall.log in a human readable format.
pfloggerd is part of Murus, a pf front end for macOS.

pfloggerd needs to be launched by root at system boot. For that purpose you should use a shell script that:
- creates the pflog0 interface needed by pf
- runs pfloggerd

For that purpose we provide an example boot plist it.murus.pfloggerd.plist.
Copy this file to /Library/LaunchDaemons/ , set its ownership to root:wheel and permission to 644. Then copy pfloggerd binary to /usr/local/bin/ . Reboot your Mac to start pfloggerd.


