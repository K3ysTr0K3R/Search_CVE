#!/bin/bash

GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
BLUE=$(tput setaf 4)
RED=$(tput setaf 1)
RESET=$(tput sgr0)

count=0
loading_cursor="/"
while getopts ":sf:" args; do
	case $args in
		s)
			result_cve=$(searchsploit --cve "$2" 2>/dev/null)
			if [ -n "$result_cve" ]; then
				echo "Results for $2"
				echo "$result_cve"
				((count++))
			else
				echo "No results found for $2"
			fi
			;;

		f)      
			clear
			echo ""
			trap 'rm search_cve.txt &>/dev/null; echo "(!) User aborted the script."; exit' INT
			cve_results=$(grep -oP "(?<=CVE-)[0-9]{4}-[0-9]{4}" "$2")
			for cve in $cve_results; do
				echo -ne "${YELLOW}(${CYAN}!${YELLOW}) ${BLUE}Searching for ${RED}CVE-${cve} ${YELLOW}[${CYAN}${loading_cursor}${YELLOW}]\r"
				result_cve=$(searchsploit --cve "$cve" 2>/dev/null)
				if [ -n "$result_cve" ]; then
					echo "[+] Results for: CVE-$cve $result_cve" | grep -vE "Exploits: No Results|Shellcodes: No Results" | cat >> search_cve.txt
					if echo "$result_cve" | grep -q "Exploit"; then
						exploit_found=true
					fi
				fi

				case $loading_cursor in
					"/") loading_cursor="-";;
					"-") loading_cursor="\\";;
					"\\") loading_cursor="|";;
					"|") loading_cursor="/";;
				esac
			done
			;;
	esac
done

clear
echo ""
if $exploit_found; then
	echo -e "${YELLOW}(${CYAN}i${YELLOW}) ${GREEN}Exploits found for the following CVEs:"
	echo ""
	CVE=$(grep -oP "(?<=CVE-)[0-9]{4}-[0-9]{4}" search_cve.txt | sort -u)
	for CVES in $CVE; do
		echo -e "${YELLOW}[${BLUE}+${YELLOW}] ${CYAN}CVE-$CVES"
		((count ++))
	done
else
	echo "No exploits found."
fi
echo ""
echo -e "${YELLOW}(${CYAN}i${YELLOW}) ${GREEN}Found ${RED}$count ${GREEN}exploits."
rm search_cve.txt
