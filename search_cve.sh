#!/bin/bash

GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
BLUE=$(tput setaf 4)
RED=$(tput setaf 1)

count=0
loading_cursor="/"
exploit_found=false
exploit_found_2=false

while getopts ":sf:d:" args; do
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
			    echo -ne "${YELLOW}(${CYAN}!${YELLOW}) ${BLUE}Searching exploits for ${RED}CVE-${cve} ${YELLOW}[${CYAN}${loading_cursor}${YELLOW}]\r"
			    result_cve=$(searchsploit --cve "$cve" 2>/dev/null)
			    if [ -n "$result_cve" ]; then
				    echo "[+] Results for: CVE-$cve $result_cve" | grep -vE "Exploits: No Results|Shellcodes: No Results" | cat >> search_cve.txt
				    if echo "$result_cve" | grep -q "Exploit"; then
					    exploit_found=true
				    fi
			    fi
			    
			    case $loading_cursor in
				    "/") loading_cursor="-" ;;
				    "-") loading_cursor="\\" ;;
				    "\\") loading_cursor="|" ;;
				    "|") loading_cursor="/" ;;
			    esac
		    done
		    ;;
	    d)
		    clear
		    echo ""
		    trap 'rm search_cve.txt &>/dev/null; echo "(!) User aborted the script."; exit' INT
		    cve_results=$(grep -oP "(?<=CVE-)[0-9]{4}-[0-9]{4}" "$2")
		    for cve in $cve_results; do
			    echo -ne "${YELLOW}(${CYAN}!${YELLOW}) ${BLUE}Searching exploits for ${RED}CVE-${cve} ${YELLOW}[${CYAN}${loading_cursor}${YELLOW}]\r"
			    result_cve=$(searchsploit --cve "$cve" 2>/dev/null)
			    if [ -n "$result_cve" ]; then
				    echo "[+] Results for: CVE-$cve $result_cve" | grep -vE "Exploits: No Results|Shellcodes: No Results" | cat >> search_cve.txt
				    if echo "$result_cve" | grep -q "Exploit"; then
					    exploit_found_2=true
				    fi
			    fi
			    
			    case $loading_cursor in
				    "/") loading_cursor="-" ;;
				    "-") loading_cursor="\\" ;;
				    "\\") loading_cursor="|" ;;
				    "|") loading_cursor="/" ;;
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
		((count++))
	done
	echo ""
	echo -e "${YELLOW}(${CYAN}i${YELLOW}) ${GREEN}Found ${RED}$count ${GREEN}exploits."
	rm search_cve.txt

elif $exploit_found_2; then
	low_scores=("1.0" "1.5" "2.0" "2.5" "3.0" "3.5" "3.9")
	medium_scores=("4.0" "4.1" "4.2" "4.3" "4.4" "4.5" "4.6" "4.7" "4.8" "4.9" "5.0" "5.1" "5.2" "5.3" "5.4" "5.5" "5.6" "5.7" "5.8" "5.9" "6.0" "6.1" "6.2" "6.3" "6.4" "6.5" "6.6" "6.7" "6.8" "6.9")
	high_scores=("7.0" "7.1" "7.2" "7.3" "7.4" "7.5" "7.6" "7.7" "7.8" "7.9" "8.0" "8.1" "8.2" "8.3" "8.4" "8.5" "8.6" "8.7" "8.8" "8.9")
	critical_scores=("9.0" "9.1" "9.2" "9.3" "9.4" "9.5" "9.6" "9.7" "9.8" "9.9" "10.0")
	cve_reports=$(grep -oP "(?<=CVE-)[0-9]{4}-[0-9]{4}" search_cve.txt | sort -u)
	for cve in $cve_reports; do
		first_check=$(curl -s "https://www.cvedetails.com/cve/CVE-$cve/?q=CVE-$cve" | html2text | grep "Products        CVSS Score" | awk '{print $4}')
		second_check=$(curl -s "https://www.cvedetails.com/cve/CVE-$cve/?q=CVE-$cve" | html2text | grep "Vendor_Search   CVSS Score" | awk '{print $4}')
		third_check=$(curl -s "https://www.cvedetails.com/cve/CVE-$cve/?q=CVE-$cve" | html2text | grep "Product_Cvss    CVSS Score" | awk '{print $4}')
		if [[ -n $first_check ]]; then
			if [[ "${low_scores[@]} " =~ "$first_check" ]]; then
				severity="LOW"
			elif [[ "${medium_scores[@]}" =~ "$first_check" ]]; then
				severity="MEDIUM"
			elif [[ " ${high_scores[@]}" =~ "$first_check" ]]; then
				severity="HIGH"
			elif [[ "${critical_scores[@]}" =~ "$first_check" ]]; then
				severity="CRITICAL"
			fi
		
		elif [[ -n $second_check ]]; then
			if [[ "${low_scores[@]} " =~ "$second_check" ]]; then
				severity="LOW"
			elif [[ "${medium_scores[@]}" =~ "$second_check" ]]; then
				severity="MEDIUM"
			elif [[ " ${high_scores[@]}" =~ "$second_check" ]]; then
				severity="HIGH"
			elif [[ "${critical_scores[@]}" =~ "$second_check" ]]; then
				severity="CRITICAL"
			fi
		
		elif [[ -n $third_check ]]; then
			if [[ "${low_scores[@]} " =~ "$third_check" ]]; then
				severity="LOW"
			elif [[ "${medium_scores[@]}" =~ "$third_check" ]]; then
				severity="MEDIUM"
			elif [[ " ${high_scores[@]}" =~ "$third_check" ]]; then
				severity="HIGH"
			elif [[ "${critical_scores[@]}" =~ "$third_check" ]]; then
				severity="CRITICAL"
			fi
		fi
		
		echo -e "${YELLOW}[${BLUE}+${YELLOW}] ${CYAN}CVE-$cve ${YELLOW}(Severity: ${severity})"
		((count++))
	done
	echo ""
	echo -e "${YELLOW}(${CYAN}i${YELLOW}) ${GREEN}Found ${RED}$count ${GREEN}CVEs with severity levels."
	rm search_cve.txt
else
	echo -e "${YELLOW}(${CYAN}i${YELLOW}) ${GREEN}No exploits or CVEs found."
fi
