# CCDC-CyberHawks
CyberHawks scripts for CCDC 

*This repo is still a work-in-progress - Lucas 2025-04-30*

## List of Scripts I want to build
- ./services-test.ps1 - Script to test services (will run on Win10)
    - I'd like this to make DNS requests and HTTP requests
    - Check what traffic can make it through the PaloAlto firewall
    - Check Host Firewall
- ./windows-setup.ps1 - Script to setup a Windows Server 2019 machine for CCDC
    - Install all the tools we need
    - Configure the host firewall
    - Check DNS service
- ./windows-check.ps1 - Script to check if the DNS server on a Windows Server 2019 server is working
    - This will run on the external win10 server
    - I want it to help us discover what is wrong with the DNS server
## Linux Scripts to Build
- kill_service.sh - Script to systemctl stop, disable, and mask a service. Also apply chmod 000, rename service config to .bak, and add the service's name to a file for logkeeping.
- find_bad_suid.sh - Script to find all files with SUID bit and compared against bad_suid list. Print out the results (bad files with SUID) and output to a file.
	- this wouldn't un-SUID them so that if there are files that should have the SUID kept after all, they can be removed from the printed list.
- kill_bad_suid.sh - Script that takes the file with files to un-SUID and does that.
- find_bad_sgid.sh, kill_bad_sgid.sh, find_bad_cap.sh, kill_bad_cap.sh - same as find_bad_suid.sh and kill_bad_suid.sh but for SGID and Capabilities.
- find_bad_services.sh - find all services print out the ones that aren't in the normal_services list/