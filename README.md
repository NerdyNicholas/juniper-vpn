# Linux Juniper VPN Tools
## Background
The Linux version of the juniper vpn client has a number of problems including

* Frequent disconnects
* Connection stops passing data
* Inablity to recover from network changes (e.g. wifi drops out, resume from standby)

When any of the above happen, the user must go back to the browser and restart the client.

The tools here make using the juniper vpn client on linux a little less painless by managing the connection automatically.   It will do things like 

* Detect network interruption, disconnect the client, and restart client when network is restored
* Detect connection is up but no longer passing data and restart the connection
* Allow user to easily disconnect and reconnect 

The tools here are based on the work done by Scott: http://makefile.com/.plan/2009/10/juniper-vpn-64-bit-linux-an-unsolved-mystery/

He figured out how to make the ncui library an executable binary and how to launch it from the command line to connect to the juniper/pulse vpn.

## Setup

1. Access your juniper vpn site using a browser to install the juniper client and necessary files
2. Install gcc-multilib packages for your Linux distribution
3. Install sqlite3
4. Download the juniper-vpn.sh script
5. Edit the script and change the vpn site and path to your cookies database (currently only reading firefox cookies is implemented)

## Using
In order to use the script you must login through the vpn web interface first.  This will authenticate you with the vpn and provide the DSID cookie.  It will also allow the vpn site to run utilities such as host checkers that some companies require.

1. Login to the vpn site and close the juniper client if it launches
2. Run the juniper-vpn.sh script. For now, this requires a dedicated terminal to interact with the script.
3. While running:
	* Hit 'q' to disconnect and exit
	* Hit 'd' to disconnect and wait
	* Hit 'r' to reconnect the vpn

Note: only basic testing has been done so expect to find some issues.

## Future
* Python qt GUI version with connect/disconnect buttons and status information
* Tray icon to allow disconnect/reconnect
* Add support for additonal browser cookies
* Add thin client browser to GUI version allowing login and connection management from one program






