#!/bin/bash

### INFO ######################################################################
# Author: Timo Sablowski
# Contact: https://www.linkedin.com/in/timo-sablowski
# License: GNU GPLv3 
###############################################################################

# Requirements to be installed
reqs="nmap xmlstarlet xsltproc httprobe nikto eyewitness elinks cmseek"

# Default options
noPingFirst=""
udpScan=true
inputFile=""
outputDir=""
runNikto=true


printRed() {
  echo -e "\e[1;31m$1\e[0m"
}

printGreen() {
  echo -e "\e[1;32m$1\e[0m"
}

checkReqs () {
	# Checks if all required programs are installed.
	missingReqs=""
	for req in `echo ${reqs}`; do
		which ${req} 2>&1>/dev/null
		ret=$?
		if [ ${ret} -ne 0 ]; then
			missingReqs="${missingReqs}${req} "
		fi
	done
	if [ -n "${missingReqs}" ]; then
		printRed "Some dependencies are missing to use the full functionality. Please make sure that the following programs are installed and available via \`which\`:"
		echo " ${missingReqs}"
		exit 1
	fi
}

printLogo () {
echo " _____   ______  _____  ____   _   _                _                              "
echo "|  __ \ |  ____|/ ____|/ __ \ | \ | |              (_)                             "
echo "| |__) || |__  | |    | |  | ||  \| | _ __    __ _  _  ___  ___   ___  _   _  _ __ "
echo "|  _  / |  __| | |    | |  | || . \ || '_ \  / _  || |/ __|/ __| / _ \| | | || '__|"
echo "| | \ \ | |____| |____| |__| || |\  || | | | |(_| || |\__ \\\\__ \|  __/| |_| || |   "
echo "|_|  \_\|______|\_____|\____/ |_| \_||_| |_| \__,_||_||___/|___/ \___| \__,_||_|   "
echo "                                                                                   "
echo "                                                                                   "


}

printHelp () {
	printLogo
	echo "This script helps you to automatically collect the most important information in the recon phase of IP networks."
	echo ""
	echo "Usage: $0 <options> <inputFile> <outputDirectory>"
	echo " <inputFile> is a text file containing hostnames, IPs or CIDR ranges."
	echo " <outputDirectory> is a clean folder where all information will be placed."
	echo " Options:"
	echo "  -h prints this help and exits."
	echo "  -p skips the nmap ping check and considers all hosts alive."
	echo "  -u skips the nmap UDP scan (default: top 100 ports)."
	echo "     the default UDP scan might ask for the sudo password."
	echo "  -n skips the nikto scan of discovered webservers."
	exit 1
}

runNmap () {
	printGreen "Running nmap: TCP scan on all ports"
	nmap -oA ${nmapTcpOutput} -T4 -A ${noPingFirst} -p- -iL ${inputFile} 2>&1>/dev/null
	ret=$?
	if [ ${ret} -ne 0 ]; then
		printRed "Problems with running nmap."
		printRed "Exiting..."
		exit 1
	fi
	echo " [+] Check nmap output at: ${nmapTcpOutput}.*"
	if ${udpScan}; then
		printGreen "Running nmap: UDP scan on top 100"
		sudo nmap -oA ${nmapUdpOutput} -sU -T4 ${noPingFirst} --top-ports 100 -iL ${inputFile} 2>&1>/dev/null
		ret=$?
		if [ ${ret} -ne 0 ]; then
			printRed "Problems with running nmap."
			printRed "Exiting..."
			exit 1
		fi
		echo " [+] Check nmap output at: ${nmapUdpOutput}.*"
	else
		printRed "Skipping UDP Scan"
	fi
}

nmapToFolders () {
	printGreen "Sorting the nmap results into individual folders"
	for host in `grep -e 'Status: Up' -e '/open/' ${nmapTcpOutput}.gnmap | cut -d " " -f 2 | sort -u`; do
		echo ${host} >> ${aliveHosts}.tmp
		mkdir -p ${outputDir}/${host}
		echo "<?xml-stylesheet href=\"/usr/share/nmap/nmap.xsl\" type=\"text/xsl\"?>" > ${outputDir}/${host}/temp.xml
		xmlstarlet sel -t -c "//host[address[@addr='${host}']]" ${nmapTcpOutput}.xml >> ${outputDir}/${host}/temp.xml
		xsltproc ${outputDir}/${host}/temp.xml -o ${outputDir}/${host}/tcpPorts.html
		rm -f ${outputDir}/${host}/temp.xml
	done
	if ${udpScan}; then
		for host in `grep -e 'Status: Up' -e '/open/' ${nmapUdpOutput}.gnmap | cut -d " " -f 2 | sort -u`; do
			echo ${host} >> ${aliveHosts}.tmp
			mkdir -p ${outputDir}/${host}
			echo "<?xml-stylesheet href=\"/usr/share/nmap/nmap.xsl\" type=\"text/xsl\"?>" > ${outputDir}/${host}/temp2.xml
			xmlstarlet sel -t -c "//host[address[@addr='${host}']]" ${nmapUdpOutput}.xml >> ${outputDir}/${host}/temp2.xml
			xsltproc ${outputDir}/${host}/temp2.xml -o ${outputDir}/${host}/udpPorts.html
			rm -f ${outputDir}/${host}/temp2.xml
		done
	fi
	echo " [+] Check the folders for individual IPs at ${outputDir}/<IP>"

	cat ${aliveHosts}.tmp | sort -u > ${aliveHosts}
	rm -f ${aliveHosts}.tmp
}

getOpenPorts () {
	printGreen "Compiling a list of all open ports"
	for host in `cat ${aliveHosts}`; do
		for port in `xmlstarlet sel -t -v "//host[address[@addr='${host}']]/ports/port[state[@state='open']]/@portid" -n ${nmapTcpOutput}.xml`; do
			echo "tcp:${host}:${port}" >> ${outputDir}/openPorts.txt
		done
		if ${udpScan}; then
			for port in `xmlstarlet sel -t -v "//host[address[@addr='${host}']]/ports/port[state[@state='open']]/@portid" -n ${nmapUdpOutput}.xml`; do
				echo "udp:${host}:${port}" >> ${outputDir}/openPorts.txt
			done
		fi
	done
	echo " [+] You will find a list of all open ports for the scanned IPs at: ${outputDir}/openPorts.txt"
}

getWebservers () {
	printGreen "Compiling a list of all web servers"
	for tcpService in `cat ${outputDir}/openPorts.txt | grep "tcp" | sed -s 's/^tcp://'`; do
		echo ${tcpService} | httprobe >> ${webServers}.tmp
	done
	cat ${webServers}.tmp | sort -u > ${webServers}
	rm -f ${webServers}.tmp
	echo " [+] A list of webservers is located at: ${webServers}"
}

screenshotWebsites () {
	printGreen "Screenshotting websites with EyeWitness"
	mkdir -p ${outputDir}/000_websites_screenshots
	eyewitness --no-prompt -f ${webServers} -d ${outputDir}/000_websites_screenshots --selenium-log-path ${outputDir}/000_websites_screenshots/selenium.log > /dev/null
	echo " [+] Screenshots of all webservers can be found at: ${outputDir}/000_websites_screenshots"
}

is_rfc1918 () {
	# Checks if an IP belongs to the RFC1918 range
    local ip=$1
    if [[ $ip =~ ^192\.168\..* ]] || [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\..* ]] || [[ $ip =~ ^10\..* ]]; then
        return 0
    else
        return 1
    fi
}

getDnsNames () {
	# Do DNS lookups
	printGreen "Searching for (historical) DNS names"
	for host in `cat ${aliveHosts}`; do
		nslookup ${host} > ${outputDir}/${host}/nslookup.txt
		if ! is_rfc1918 ${host}; then
			# If it is a public IP address lookup the DNS history of this host
			echo "Check out: https://securitytrails.com/list/ip/${host}" > ${outputDir}/${host}/possible_dns_history.txt
			echo "If there is no info below this line you have to open the website manually because of scraping restrictions." >> ${outputDir}/${host}/possible_dns_history.txt
			elinks -dump https://securitytrails.com/list/ip/${host} | grep "https://securitytrails.com/domain" | sed -s 's/^.*\/domain\///g' | sed -s 's/\/dns$//g' | sort -u >> ${outputDir}/${host}/possible_dns_history.txt
		fi
	done
	echo " [+] You will find (historical) DNS lookups for each host at: ${outputDir}/<IP>"
}

niktoOnWebsites () {
	if ${runNikto}; then
		printGreen "Running nikto on each webserver"
		for webserver in `cat ${webServers}`; do
			host=`echo ${webserver} | cut -d ":" -f 2 | sed -s 's#//##g'`
			urlName=`echo ${webserver} | sed -s 's#//##g' | sed -s 's/:/_/g'` # for naming the file
			nikto -h ${webserver} -output ${outputDir}/${host}/nikto_${urlName}.txt -ask no 2>&1>/dev/null
		done
		echo " [+] You will find the nikto output for each webserver at: ${outputDir}/<IP>/nikto_*"
	else
		printRed "Skipping scanning with nikto"
	fi
}

CmsScan () {
	printGreen "Running cmseek on each webserver"
	for webserver in `cat ${webServers}`; do
			host=`echo ${webserver} | cut -d ":" -f 2 | sed -s 's#//##g'`
			urlName=`echo ${webserver} | sed -s 's#//##g' | sed -s 's/:/_/g'` # for naming the file
			cmseek -u ${webserver} > ${outputDir}/${host}/cmseek_${urlName}.txt
	done
	echo " [+] You will find the cmseek output for each webserver at: ${outputDir}/<IP>/cmseek_*"
}


#
# MAIN
#

checkReqs

while getopts "hpun" option; do
	case ${option} in
		h) printHelp;;
		p) noPingFirst="-Pn";;
		u) udpScan=false;;
		n) runNikto=false;;
	esac
done
shift $((OPTIND - 1))
inputFile=$1
outputDir=$2

nmapTcpOutput="${outputDir}/nmapscan_tcp_allPorts_allDetections"
nmapUdpOutput="${outputDir}/nmapscan_udp_top100"
aliveHosts="${outputDir}/aliveHosts.txt"
webServers="${outputDir}/webServers.txt"


if ! test -f "${inputFile}"; then
    printRed "File ${inputFile} does not exist."
    printRed "Try -h for help."
    exit 1
fi

if ! test -d "${outputDir}"; then
    printRed "Directory ${outputDir} does not exist."
    printRed "Try -h for help."
    exit 1
fi


printLogo
runNmap
nmapToFolders
getOpenPorts
getDnsNames
getWebservers
screenshotWebsites
CmsScan
niktoOnWebsites

echo ""
echo "Consider conducting a vulnerability scan on all alive hosts: ${aliveHosts}"