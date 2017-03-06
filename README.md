# Linux Juniper VPN Tools
## Background
The web/java based Linux version of the juniper vpn client has a number of problems including

* Frequent disconnects
* Connection stops passing data
* Inablity to recover from network changes (e.g. wifi drops out, resume from standby)

When any of the above happens, the user must go back to the browser and restart the client.

A new "pulse secure" client is now available for Linux: https://kb.pulsesecure.net/articles/Pulse_Secure_Article/KB40126

However, this tool has problems as well:
* Broken post install scripts require system manipulation to install
* Host checker does not work and therefore prevents connections

The tools here are based on the work done by Scott: http://makefile.com/.plan/2009/10/juniper-vpn-64-bit-linux-an-unsolved-mystery/ and Alex Samorukov https://github.com/samm-git/jvpn/ (this code was invaluable for understanding how to get the host checker working)

## Linux Tools
The two tools here offer alternatives to connect to a juniper vpn from Linux and add additional features not found in the web/java version and pulse secure clients.
The tools include:

* juniper-vpn.sh: Script to connect from console (at present requries signing in from firefox browser)
* jgui: PyQt4 based graphical client

Both tools do the following:
* Detect network interruption, disconnect the client, and restart client when network is restored
* Detect connection is up but no longer passing data and restart the connection
* Allow user to easily disconnect and reconnect without a browser

Additionally, jgui provides:
* Graphical interface that hides in the system tray
* Configuration interface for setting host, realm, etc
* Sign in tab for inputting credentinals, signing in/out, and showing sign in status
* Connection tab for connecting/disconnecting and providing connection status

## jgui Graphical client
### Setup/Install

1. Access your juniper vpn site using a browser in order to install the juniper client and necessary files
2. Install gcc-multilib packages for your Linux distribution
3. Compile ncui_wrapper.c with command "gcc -m32 ncui_wrapper.c -ldl -o ncui_wrapper"
4. Move/copy ncui_wrapper to ~/.juniper_networks/network_connect
5. Make ncui_wrapper setuid root "chown root:root ncui_wrapper; chmod +s ncui_wrapper"
6. Install dependencies
	python-qt4
	python-enum34
	python-netifaces
7. Run jgui with command "python juniper-gui/jgui"

### Using
* In the configuration tab, input the necessary configuration
	* The login realm is the cookie used by your juniper vpn for one time passwords (e.g.: otp-std-company)
	* The url number is the part of the url when logging in (e.g.: url_15)
* In the sign in tab input username, pin, and token and click sign in
* Use the connection tab to disconnect/reconnect once signed in
* Check keep alive on the connection tab to monitor the connection and reconnect when the connection fails


## juniper-gui.sh script
### Setup

1. Access your juniper vpn site using a browser to install the juniper client and necessary files
2. Install gcc-multilib packages for your Linux distribution
3. Install sqlite3
4. Download the juniper-vpn.sh script
5. Edit the script and change the vpn site and path to your cookies database (currently only reading firefox cookies is implemented)

### Using
In order to use the script you must login through the vpn web interface first.  This will authenticate you with the vpn and provide the DSID cookie.  It will also allow the vpn site to run utilities such as host checkers that some companies require.

1. Login to the vpn site and close the juniper client if it launches
2. Run the juniper-vpn.sh script. For now, this requires a dedicated terminal to interact with the script.
3. While running:
	* Hit 'q' to disconnect and exit
	* Hit 'd' to disconnect and wait
	* Hit 'r' to reconnect the vpn

Note: only basic testing has been done so expect to find some issues.

## Future
* Deb and RPM packages
* Command line client based on python gui version (removes need for juniper-vpn.sh)

## Known issues
* Exiting the client kills the host checker so you must sign in again after restarting the client even if you never signed out
* Only supports 2 factor authentication and host checkers





