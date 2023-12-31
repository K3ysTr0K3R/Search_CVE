#!/bin/bash

GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
BLUE=$(tput setaf 4)
RED=$(tput setaf 1)
WHITE=$(tput setaf 7)
MAGENTA=$(tput setaf 5)

ascii_art(){
        echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗"
	echo -e "${GREEN}║${RED}     _____                      __        _______    ________  ${GREEN}║"
	echo -e "${GREEN}║${RED}    / ___/___  ____ ___________/ /_      / ____/ |  / / ____/  ${GREEN}║"
	echo -e "${GREEN}║${RED}    \__ \/ _ \/ __  / ___/ ___/ __ \    / /    | | / / __/     ${GREEN}║"
	echo -e "${GREEN}║${RED}   ___/ /  __/ /_/ / /  / /__/ / / /   / /___  | |/ / /___     ${GREEN}║"
	echo -e "${GREEN}║${RED}  /____/\___/\__,_/_/   \___/_/ /_/____\____/  |___/_____/     ${GREEN}║"
	echo -e "${GREEN}║${RED}                                 /_____/                       ${GREEN}║"
        echo -e "${GREEN}║═══════════════════════════════════════════════════════════════║"
        echo -e "${GREEN}║${YELLOW}                     Author: K3ysTr0K3R                        ${GREEN}║"
        echo -e "${GREEN}║${YELLOW}             GitHub: https://github.com/K3ysTr0K3R             ${GREEN}║"
        echo -e "${GREEN}║${YELLOW}                  Instagram: 1_k3ystr0k3r_1                    ${GREEN}║"
        echo -e "${GREEN}║${YELLOW}                 Coded with ❤️  by K3ysTr0K3R                   ${GREEN}║"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝"
}

count=0
loading_cursor="/"
help_menu=false
exploit_found=false
check_severity=false
check_msfconsole=false

while getopts ":hs:f:c:m" args; do
    case $args in
	    h)
		    help_menu=true
		    ;;
	    s)
		    ascii_art
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
	    c)
		    clear
		    echo ""
		    trap 'rm search_cve.txt &>/dev/null; echo "(!) User aborted the script."; exit' INT
		    ascii_art
		    cve_results=$(grep -oP "(?<=CVE-)[0-9]{4}-[0-9]{4}" "$2")
		    echo ""
		    for cve in $cve_results; do
			    echo -ne "${YELLOW}(${CYAN}!${YELLOW}) ${BLUE}Searching exploits for ${RED}CVE-${cve} ${YELLOW}[${CYAN}${loading_cursor}${YELLOW}]\r"
			    result_cve=$(searchsploit --cve "$cve" 2>/dev/null)
			    if [ -n "$result_cve" ]; then
				    echo "[+] Results for: CVE-$cve $result_cve" | grep -vE "Exploits: No Results|Shellcodes: No Results" | cat >> search_cve.txt
				    if echo "$result_cve" | grep -q "Exploit"; then
					    check_severity=true
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
	    m)
		    clear
		    echo ""
		    trap 'rm search_cve.txt &>/dev/null; echo "(!) User aborted the script."; exit' INT
                    ascii_art
		    cve_results=$(grep -oP "(?<=CVE-)[0-9]{4}-[0-9]{4}" "$2")
		    echo ""
		    for cve in $cve_results; do
			    echo -ne "${YELLOW}(${CYAN}!${YELLOW}) ${BLUE}Searching exploits for ${RED}CVE-${cve} ${YELLOW}[${CYAN}${loading_cursor}${YELLOW}]\r"
			    result_cve=$(searchsploit --cve "$cve" 2>/dev/null)
			    if [ -n "$result_cve" ]; then
				    echo "[+] Results for: CVE-$cve $result_cve" | grep -vE "Exploits: No Results|Shellcodes: No Results" | cat >> search_cve.txt
				    if echo "$result_cve" | grep -q "Exploit"; then
					    check_msfconsole=true
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
if $help_menu; then
	ascii_art
	echo -e "${WHITE}"
	echo "usage: search_cve.sh [options] [argument]"
	echo "Options:"
	echo "  -s <cve>    Search for exploits related to the specified CVE."
	echo "  -f <file>   Search for exploits related to the CVEs listed in the file."
	echo "  -c <file>   Search for exploits related to the CVEs listed in the file and check severity levels."
        echo "  -f <file>   Search for exploits related to the CVEs listed in the file and check msfconsole(Metasploit) modules."
	echo ""
	echo "Example:"
	echo "  search_cve.sh -s CVE-2021-1234"
	echo "  search_cve.sh -f cve_list.txt"
	echo "  search_cve.sh -c cve_list.txt"
	echo "  search_cve.sh -m cve_list.txt"
fi

if $exploit_found; then
	ascii_art
	echo ""
	echo -e "${YELLOW}(${CYAN}i${YELLOW}) ${GREEN}Exploits found for the following CVEs from: ${RED}$2"
	echo ""
	CVE=$(grep -oP "(?<=CVE-)[0-9]{4}-[0-9]{4}" search_cve.txt | sort -u)
	for CVES in $CVE; do
		echo -e "${YELLOW}[${BLUE}+${YELLOW}] ${CYAN}CVE-$CVES"
		((count++))
	done
	echo ""
	echo -e "${YELLOW}(${CYAN}i${YELLOW}) ${GREEN}Found ${RED}$count ${GREEN}exploits."
	rm search_cve.txt
#else
        #echo -e "${YELLOW}(${CYAN}i${YELLOW}) ${GREEN}No exploits or CVEs found."
fi

if $check_severity; then
	ascii_art
	echo ""
	echo -e "${YELLOW}(${CYAN}!${YELLOW}) ${GREEN}Checking for the severity level of each CVE found to be exploitable from: ${RED}$2"
        echo ""
	low_scores=("1.0" "1.5" "2.0" "2.5" "3.0" "3.5" "3.9")
	medium_scores=("4.0" "4.1" "4.2" "4.3" "4.4" "4.5" "4.6" "4.7" "4.8" "4.9" "5.0" "5.1" "5.2" "5.3" "5.4" "5.5" "5.6" "5.7" "5.8" "5.9" "6.0" "6.1" "6.2" "6.3" "6.4" "6.5" "6.6" "6.7" "6.8" "6.9")
	high_scores=("7.0" "7.1" "7.2" "7.3" "7.4" "7.5" "7.6" "7.7" "7.8" "7.9" "8.0" "8.1" "8.2" "8.3" "8.4" "8.5" "8.6" "8.7" "8.8" "8.9")
	critical_scores=("9.0" "9.1" "9.2" "9.3" "9.4" "9.5" "9.6" "9.7" "9.8" "9.9" "10.0")
	cve_reports=$(grep -oP "(?<=CVE-)[0-9]{4}-[0-9]{4}" search_cve.txt | sort -u)
	for cve in $cve_reports; do
		first_check=$(curl -s "https://www.cvedetails.com/cve/CVE-$cve/?q=CVE-$cve" | html2text | grep "Products        CVSS Score" | awk '{print $4}')
		second_check=$(curl -s "https://www.cvedetails.com/cve/CVE-$cve/?q=CVE-$cve" | html2text | grep "Vendor_Search   CVSS Score" | awk '{print $4}')
		third_check=$(curl -s "https://www.cvedetails.com/cve/CVE-$cve/?q=CVE-$cve" | html2text | grep "Product_Cvss    CVSS Score" | awk '{print $4}')
                fourth_check=$(curl -s "https://www.cvedetails.com/cve/CVE-$cve/?q=CVE-$cve" | html2text | grep "Scores Versions CVSS Score" | awk '{print $5}')
		if [[ -n $first_check ]]; then
			if [[ "${low_scores[@]} " =~ "$first_check" ]]; then
				severity="${GREEN}LOW"
			elif [[ "${medium_scores[@]}" =~ "$first_check" ]]; then
				severity="${YELLOW}MEDIUM"
			elif [[ " ${high_scores[@]}" =~ "$first_check" ]]; then
				severity="${YELLOW}HIGH"
			elif [[ "${critical_scores[@]}" =~ "$first_check" ]]; then
				severity="${RED}CRITICAL"
			fi

		elif [[ -n $second_check ]]; then
			if [[ "${low_scores[@]} " =~ "$second_check" ]]; then
				severity="${GREEN}LOW"
			elif [[ "${medium_scores[@]}" =~ "$second_check" ]]; then
				severity="${YELLOW}MEDIUM"
			elif [[ " ${high_scores[@]}" =~ "$second_check" ]]; then
				severity="${YELLOW}HIGH"
			elif [[ "${critical_scores[@]}" =~ "$second_check" ]]; then
				severity="${RED}CRITICAL"
			fi

		elif [[ -n $third_check ]]; then
			if [[ "${low_scores[@]} " =~ "$third_check" ]]; then
				severity="${GREEN}LOW"
			elif [[ "${medium_scores[@]}" =~ "$third_check" ]]; then
				severity="${YELLOW}MEDIUM"
			elif [[ " ${high_scores[@]}" =~ "$third_check" ]]; then
				severity="${YELLOW}HIGH"
			elif [[ "${critical_scores[@]}" =~ "$third_check" ]]; then
				severity="${RED}CRITICAL"
			fi
                elif [[ -n $fourth_check ]]; then
                        if [[ "${low_scores[@]} " =~ "$fourth_check" ]]; then
                                severity="${GREEN}LOW"
                        elif [[ "${medium_scores[@]}" =~ "$fourth_check" ]]; then
                                severity="${YELLOW}MEDIUM"
                        elif [[ " ${high_scores[@]}" =~ "$fourth_check" ]]; then
                                severity="${YELLOW}HIGH"
                        elif [[ "${critical_scores[@]}" =~ "$fourth_check" ]]; then
                                severity="${RED}CRITICAL"
                        fi
		fi

		echo -e "${YELLOW}[${BLUE}+${YELLOW}] ${CYAN}CVE-$cve ${MAGENTA}(${CYAN}SEVERITY${BLUE}:${severity}${MAGENTA})"
		((count++))
	done
	echo ""
	echo -e "${YELLOW}(${CYAN}i${YELLOW}) ${GREEN}Found ${RED}$count ${GREEN}CVEs with exploits & severity levels."
	rm search_cve.txt
#else
#	echo -e "${YELLOW}(${CYAN}i${YELLOW}) ${GREEN}No exploits or CVEs with severity levels found."
fi

if $check_msfconsole; then
	ascii_art
	echo ""
	echo -e "${YELLOW}(${CYAN}!${YELLOW}) ${GREEN}Checking for available ${YELLOW}msfconsole${MAGENTA}(${YELLOW}Metasploit${MAGENTA}) ${GREEN}modules from each CVE found from${BLUE}: ${RED}$2"
        echo ""
	cve_exploit_modules=$(grep -oP "(?<=CVE-)[0-9]{4}-[0-9]{4}" search_cve.txt | sort -u)
	for cve_msfconsole in $cve_exploit_modules; do
		msfconsole_modules_aux=$(msfconsole -qx "search CVE:$cve_msfconsole; exit" 2>/dev/null | grep "auxiliary/" | awk 'NR==1{print $2}')
                msfconsole_modules_exp=$(msfconsole -qx "search CVE:$cve_msfconsole; exit" 2>/dev/null | grep "exploit/" | awk 'NR==1{print $2}')
		if [ -n "$msfconsole_modules_aux" ]; then
			echo -e "${YELLOW}[${BLUE}+${YELLOW}] ${CYAN}CVE-$cve_msfconsole ${MAGENTA}(${CYAN}MODULES${BLUE}:${GREEN}$msfconsole_modules_aux${MAGENTA})"
		elif [ -n "$msfconsole_modules_exp" ]; then
			echo -e "${YELLOW}[${BLUE}+${YELLOW}] ${CYAN}CVE-$cve_msfconsole ${MAGENTA}(${CYAN}MODULES${BLUE}:${GREEN}$msfconsole_modules_exp${MAGENTA})"
		else
			continue
		fi
                ((count++))
	done
        echo ""
        echo -e "${YELLOW}(${CYAN}i${YELLOW}) ${GREEN}Found ${RED}$count ${GREEN}CVEs with exploits from ${YELLOW}msfconsole${MAGENTA}(${YELLOW}Metasploit${MAGENTA})${GREEN}."
fi
