#!/usr/bin/env bash
stty erase ^h
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: Debian/Ubuntu
#	Description: ocserv AnyConnect
#	Version: 1.0.20
#=================================================
sh_ver="1.0.20"
file="/usr/local/sbin/ocserv"
conf_file="/etc/ocserv"
conf="/etc/ocserv/ocserv.conf"
passwd_file="/etc/ocserv/ocpasswd"
log_file="/tmp/ocserv.log"
ocserv_ver="0.12.6"
PID_FILE="/var/run/ocserv.pid"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[information]${Font_color_suffix}"
Error="${Red_font_prefix}[mistakestake]${Font_color_suffix}"
Tip="${Green_font_prefix}[Notice]${Font_color_suffix}"

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} The current non-ROOT account (or no ROOT authority), cannot continue to operate, please change the ROOT account or use ${Green_background_prefix}sudo su${Font_color_suffix} command to obtain temporary ROOT privileges (after execution, you may be prompted to enter the password of the current account)." && exit 1
}

check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	#bit=`uname -m`
}
check_installed_status(){
	[[ ! -e ${file} ]] && echo -e "${Error} ocserv not installed, please check !" && exit 1
	[[ ! -e ${conf} ]] && echo -e "${Error} ocserv The configuration file does not exist, please check !" && [[ $1 != "un" ]] && exit 1
}
check_pid(){
	if [[ ! -e ${PID_FILE} ]]; then
		PID=""
	else
		PID=$(cat ${PID_FILE})
	fi
}
Get_ip(){
	ip=$(wget -qO- -t1 -T2 api.ip.la)
	if [[ -z "${ip}" ]]; then
		ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ip}" ]]; then
			ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ip}" ]]; then
				ip="VPS_IP"
			fi
		fi
	fi
}
Download_ocserv(){
	mkdir "ocserv" && cd "ocserv"
	wget "ftp://ftp.infradead.org/pub/ocserv/ocserv-${ocserv_ver}.tar.xz"
	[[ ! -s "ocserv-${ocserv_ver}.tar.xz" ]] && echo -e "${Error} ocserv Source file download failed !" && rm -rf "ocserv/" && rm -rf "ocserv-${ocserv_ver}.tar.xz" && exit 1
	tar -xJf ocserv-${ocserv_ver}.tar.xz && cd ocserv-${ocserv_ver}
	./configure
	make
	make install
	cd .. && cd ..
	rm -rf ocserv/
	
	if [[ -e ${file} ]]; then
		mkdir "${conf_file}"
		wget --no-check-certificate -N -P "${conf_file}" "https://raw.githubusercontent.com/lllvcs/ocserv/master/ocserv.conf"
		[[ ! -s "${conf}" ]] && echo -e "${Error} ocserv Configuration file download failed !" && rm -rf "${conf_file}" && exit 1
	else
		echo -e "${Error} ocserv Compilation and installation failed, please check！" && exit 1
	fi
}
Service_ocserv(){
	if ! wget --no-check-certificate https://raw.githubusercontent.com/lllvcs/ocserv/master/ocserv_debian -O /etc/init.d/ocserv; then
		echo -e "${Error} ocserv Services Management script download failed !" && over
	fi
	chmod +x /etc/init.d/ocserv
	update-rc.d -f ocserv defaults
	echo -e "${Info} ocserv Service management script download complete !"
}
rand(){
	min=10000
	max=$((60000-$min+1))
	num=$(date +%s%N)
	echo $(($num%$max+$min))
}
Generate_SSL(){
	lalala=$(rand)
	mkdir /tmp/ssl && cd /tmp/ssl
	echo -e 'cn = "'${lalala}'"
organization = "'${lalala}'"
serial = 1
expiration_days = 365
ca
signing_key
cert_signing_key
crl_signing_key' > ca.tmpl
	[[ $? != 0 ]] && echo -e "${Error} Failed to write SSL certificate signature template(ca.tmpl) !" && over
	certtool --generate-privkey --outfile ca-key.pem
	[[ $? != 0 ]] && echo -e "${Error} Failed to generate SSL certificate key file(ca-key.pem) !" && over
	certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile ca-cert.pem
	[[ $? != 0 ]] && echo -e "${Error} Failed to generate SSL certificate file(ca-cert.pem) !" && over
	
	Get_ip
	if [[ -z "$ip" ]]; then
		echo -e "${Error} Failed to detect external network IP !"
		read -e -p "Please manually enter your server extranet IP:" ip
		[[ -z "${ip}" ]] && echo "Cancel..." && over
	fi
	echo -e 'cn = "'${ip}'"
organization = "'${lalala}'"
expiration_days = 365
signing_key
encryption_key
tls_www_server' > server.tmpl
	[[ $? != 0 ]] && echo -e "${Error} Written SSL certificate signature template failed(server.tmpl) !" && over
	certtool --generate-privkey --outfile server-key.pem
	[[ $? != 0 ]] && echo -e "${Error} Failure to generate the SSL certificate key file(server-key.pem) !" && over
	certtool --generate-certificate --load-privkey server-key.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template server.tmpl --outfile server-cert.pem
	[[ $? != 0 ]] && echo -e "${Error} Failure to generate the SSL certificate file(server-cert.pem) !" && over
	
	mkdir /etc/ocserv/ssl
	mv ca-cert.pem /etc/ocserv/ssl/ca-cert.pem
	mv ca-key.pem /etc/ocserv/ssl/ca-key.pem
	mv server-cert.pem /etc/ocserv/ssl/server-cert.pem
	mv server-key.pem /etc/ocserv/ssl/server-key.pem
	cd .. && rm -rf /tmp/ssl/
}
Installation_dependency(){
	[[ ! -e "/dev/net/tun" ]] && echo -e "${Error} Your VPS does not turn on the TUN, please contact the IDC or open the TUN/TAP switch through the VPS control panel !" && exit 1
	if [[ ${release} = "centos" ]]; then
		echo -e "${Error} This script does not support the CentOS system!" && exit 1
	elif [[ ${release} = "debian" ]]; then
		cat /etc/issue |grep 9\..*>/dev/null
		if [[ $? = 0 ]]; then
			apt-get update
			apt-get install vim net-tools pkg-config build-essential libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin -y
		else
			mv /etc/apt/sources.list /etc/apt/sources.list.bak
			wget --no-check-certificate -O "/etc/apt/sources.list" "https://raw.githubusercontent.com/lllvcs/doubi/master/sources/aliyun.sources.list"
			apt-get update
			apt-get install vim net-tools pkg-config build-essential libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin -y
			rm -rf /etc/apt/sources.list
			mv /etc/apt/sources.list.bak /etc/apt/sources.list
			apt-get update
		fi
	else
		apt-get update
		apt-get install vim net-tools pkg-config build-essential libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin -y
	fi
}
Install_ocserv(){
	check_root
	[[ -e ${file} ]] && echo -e "${Error} ocserv Established, please check !" && exit 1
	echo -e "${Info} Start installation/configuration dependencies..."
	Installation_dependency
	echo -e "${Info} Start download/install configuration file..."
	Download_ocserv
	echo -e "${Info} Start download/install service script(init)..."
	Service_ocserv
	echo -e "${Info} Start signing SSL certificate..."
	Generate_SSL
	echo -e "${Info} Start setting account configuration..."
	Read_config
	Set_Config
	echo -e "${Info} Start setting iptables firewall..."
	Set_iptables
	echo -e "${Info} Start adding iptables firewall rules..."
	Add_iptables
	echo -e "${Info} Start saving iptables firewall rules..."
	Save_iptables
	echo -e "${Info} After all steps are installed, start starting..."
	Start_ocserv
}
Start_ocserv(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} ocserv It is running, please check !" && exit 1
	/etc/init.d/ocserv start
	sleep 2s
	check_pid
	[[ ! -z ${PID} ]] && View_Config
}
Stop_ocserv(){
	check_installed_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} ocserv No operation, please check !" && exit 1
	/etc/init.d/ocserv stop
}
Restart_ocserv(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/ocserv stop
	/etc/init.d/ocserv start
	sleep 2s
	check_pid
	[[ ! -z ${PID} ]] && View_Config
}
Set_ocserv(){
	[[ ! -e ${conf} ]] && echo -e "${Error} ocserv The configuration file does not exist !" && exit 1
	tcp_port=$(cat ${conf}|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
	udp_port=$(cat ${conf}|grep "udp-port ="|awk -F ' = ' '{print $NF}')
	vim ${conf}
	set_tcp_port=$(cat ${conf}|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
	set_udp_port=$(cat ${conf}|grep "udp-port ="|awk -F ' = ' '{print $NF}')
	Del_iptables
	Add_iptables
	Save_iptables
	echo "Whether to restart ocserv ? (Y/n)"
	read -e -p "(默认: Y):" yn
	[[ -z ${yn} ]] && yn="y"
	if [[ ${yn} == [Yy] ]]; then
		Restart_ocserv
	fi
}
Set_username(){
	echo "Please enter the VPN account user name to be added"
	read -e -p "(default: name-of-user):" username
	[[ -z "${username}" ]] && username="name-of-user"
	echo && echo -e "	username : ${Red_font_prefix}${username}${Font_color_suffix}" && echo
}
Set_passwd(){
	echo "Please enter the VPN account password to be added"
	read -e -p "(default: your-passcode):" userpass
	[[ -z "${userpass}" ]] && userpass="your-passcode"
	echo && echo -e "	password: ${Red_font_prefix}${userpass}${Font_color_suffix}" && echo
}
Set_tcp_port(){
	while true
	do
	echo -e "Please enter the TCP port of the VPN server"
	read -e -p "(default: 443):" set_tcp_port
	[[ -z "$set_tcp_port" ]] && set_tcp_port="443"
	echo $((${set_tcp_port}+0)) &>/dev/null
	if [[ $? -eq 0 ]]; then
		if [[ ${set_tcp_port} -ge 1 ]] && [[ ${set_tcp_port} -le 65535 ]]; then
			echo && echo -e "	TCP port : ${Red_font_prefix}${set_tcp_port}${Font_color_suffix}" && echo
			break
		else
			echo -e "${Error} Please enter the correct number！"
		fi
	else
		echo -e "${Error} Please enter the correct number！"
	fi
	done
}
Set_udp_port(){
	while true
	do
	echo -e "Please enter the UDP port of the VPN server"
	read -e -p "(default: ${set_tcp_port}):" set_udp_port
	[[ -z "$set_udp_port" ]] && set_udp_port="${set_tcp_port}"
	echo $((${set_udp_port}+0)) &>/dev/null
	if [[ $? -eq 0 ]]; then
		if [[ ${set_udp_port} -ge 1 ]] && [[ ${set_udp_port} -le 65535 ]]; then
			echo && echo -e "	TCP port : ${Red_font_prefix}${set_udp_port}${Font_color_suffix}" && echo
			break
		else
			echo -e "${Error} Please enter the correct number！"
		fi
	else
		echo -e "${Error} Please enter the correct number！"
	fi
	done
}
Set_Config(){
	Set_username
	Set_passwd
	echo -e "${userpass}\n${userpass}"|ocpasswd -c ${passwd_file} ${username}
	Set_tcp_port
	Set_udp_port
	sed -i 's/tcp-port = '"$(echo ${tcp_port})"'/tcp-port = '"$(echo ${set_tcp_port})"'/g' ${conf}
	sed -i 's/udp-port = '"$(echo ${udp_port})"'/udp-port = '"$(echo ${set_udp_port})"'/g' ${conf}
}
Read_config(){
	[[ ! -e ${conf} ]] && echo -e "${Error} ocserv The configuration file does not exist !" && exit 1
	conf_text=$(cat ${conf}|grep -v '#')
	tcp_port=$(echo -e "${conf_text}"|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
	udp_port=$(echo -e "${conf_text}"|grep "udp-port ="|awk -F ' = ' '{print $NF}')
	max_same_clients=$(echo -e "${conf_text}"|grep "max-same-clients ="|awk -F ' = ' '{print $NF}')
	max_clients=$(echo -e "${conf_text}"|grep "max-clients ="|awk -F ' = ' '{print $NF}')
}
List_User(){
	[[ ! -e ${passwd_file} ]] && echo -e "${Error} ocserv Account configuration file does not exist !" && exit 1
	User_text=$(cat ${passwd_file})
	if [[ ! -z ${User_text} ]]; then
		User_num=$(echo -e "${User_text}"|wc -l)
		user_list_all=""
		for((integer = 1; integer <= ${User_num}; integer++))
		do
			user_name=$(echo -e "${User_text}" | awk -F ':*:' '{print $1}' | sed -n "${integer}p")
			user_status=$(echo -e "${User_text}" | awk -F ':*:' '{print $NF}' | sed -n "${integer}p"|cut -c 1)
			if [[ ${user_status} == '!' ]]; then
				user_status="Disable"
			else
				user_status="Open up"
			fi
			user_list_all=${user_list_all}"username: "${user_name}" Account status: "${user_status}"\n"
		done
		echo && echo -e "Total number of users ${Green_font_prefix}"${User_num}"${Font_color_suffix}"
		echo -e ${user_list_all}
	fi
}
Add_User(){
	Set_username
	Set_passwd
	user_status=$(cat "${passwd_file}"|grep "${username}"':*:')
	[[ ! -z ${user_status} ]] && echo -e "${Error} Username already exists ![ ${username} ]" && exit 1
	echo -e "${userpass}\n${userpass}"|ocpasswd -c ${passwd_file} ${username}
	user_status=$(cat "${passwd_file}"|grep "${username}"':*:')
	if [[ ! -z ${user_status} ]]; then
		echo -e "${Info} Account added successfully ![ ${username} ]"
	else
		echo -e "${Error} Account adding failure ![ ${username} ]" && exit 1
	fi
}
Del_User(){
	List_User
	[[ ${User_num} == 1 ]] && echo -e "${Error} At present, there is only one account configuration that cannot be deleted !" && exit 1
	echo -e "Please enter the user name of the VPN account to be deleted"
	read -e -p "(Cancel down by default):" Del_username
	[[ -z "${Del_username}" ]] && echo "Cancelled..." && exit 1
	user_status=$(cat "${passwd_file}"|grep "${Del_username}"':*:')
	[[ -z ${user_status} ]] && echo -e "${Error} Username does not exist ! [${Del_username}]" && exit 1
	ocpasswd -c ${passwd_file} -d ${Del_username}
	user_status=$(cat "${passwd_file}"|grep "${Del_username}"':*:')
	if [[ -z ${user_status} ]]; then
		echo -e "${Info} successfully deleted ! [${Del_username}]"
	else
		echo -e "${Error} failed to delete ! [${Del_username}]" && exit 1
	fi
}
Modify_User_disabled(){
	List_User
	echo -e "Please enter the user name of the VPN account to be enabled/disabled"
	read -e -p "(Cancel down by default):" Modify_username
	[[ -z "${Modify_username}" ]] && echo "Cancelled..." && exit 1
	user_status=$(cat "${passwd_file}"|grep "${Modify_username}"':*:')
	[[ -z ${user_status} ]] && echo -e "${Error} Username does not exist ! [${Modify_username}]" && exit 1
	user_status=$(cat "${passwd_file}" | grep "${Modify_username}"':*:' | awk -F ':*:' '{print $NF}' |cut -c 1)
	if [[ ${user_status} == '!' ]]; then
			ocpasswd -c ${passwd_file} -u ${Modify_username}
			user_status=$(cat "${passwd_file}" | grep "${Modify_username}"':*:' | awk -F ':*:' '{print $NF}' |cut -c 1)
			if [[ ${user_status} != '!' ]]; then
				echo -e "${Info} Successful ! [${Modify_username}]"
			else
				echo -e "${Error} Enable failure ! [${Modify_username}]" && exit 1
			fi
		else
			ocpasswd -c ${passwd_file} -l ${Modify_username}
			user_status=$(cat "${passwd_file}" | grep "${Modify_username}"':*:' | awk -F ':*:' '{print $NF}' |cut -c 1)
			if [[ ${user_status} == '!' ]]; then
				echo -e "${Info} Disable ! [${Modify_username}]"
			else
				echo -e "${Error} Disable failure ! [${Modify_username}]" && exit 1
			fi
		fi
}
Set_Pass(){
	check_installed_status
	echo && echo -e " what are you going to do?
	
 ${Green_font_prefix} 0.${Font_color_suffix} List account configuration
————————
 ${Green_font_prefix} 1.${Font_color_suffix} Add account configuration
 ${Green_font_prefix} 2.${Font_color_suffix} Delete account configuration
————————
 ${Green_font_prefix} 3.${Font_color_suffix} Enable/disable account configuration
 
Note: After adding/modify/delete the account configuration, the VPN server will be read in real time without restarting the server!" && echo
	read -e -p "(Default: Cancel):" set_num
	[[ -z "${set_num}" ]] && echo "Cancelled..." && exit 1
	if [[ ${set_num} == "0" ]]; then
		List_User
	elif [[ ${set_num} == "1" ]]; then
		Add_User
	elif [[ ${set_num} == "2" ]]; then
		Del_User
	elif [[ ${set_num} == "3" ]]; then
		Modify_User_disabled
	else
		echo -e "${Error} Please enter the correct number[1-3]" && exit 1
	fi
}
View_Config(){
	Get_ip
	Read_config
	clear && echo "===================================================" && echo
	echo -e " AnyConnect Configuration information：" && echo
	echo -e " IP\t\t  : ${Green_font_prefix}${ip}${Font_color_suffix}"
	echo -e " TCP port \t  : ${Green_font_prefix}${tcp_port}${Font_color_suffix}"
	echo -e " UDP port \t  : ${Green_font_prefix}${udp_port}${Font_color_suffix}"
	echo -e " Single user device number limit: ${Green_font_prefix}${max_same_clients}${Font_color_suffix}"
	echo -e " Total user equipment number restriction : ${Green_font_prefix}${max_clients}${Font_color_suffix}"
	echo -e "\n Please fill in the client link : ${Green_font_prefix}${ip}:${tcp_port}${Font_color_suffix}"
	echo && echo "==================================================="
}
View_Log(){
	[[ ! -e ${log_file} ]] && echo -e "${Error} ocserv The log file does not exist !" && exit 1
	echo && echo -e "${Tip} 按 ${Red_font_prefix}Ctrl+C${Font_color_suffix} Termine view log" && echo -e "If you need to view the full log content, please use it ${Red_font_prefix} cat ${log_file}${Font_color_suffix} Order." && echo
	tail -f ${log_file}
}
Uninstall_ocserv(){
	check_installed_status "un"
	echo "Determine to uninstall ocserv ? (y/N)"
	echo
	read -e -p "(default: n):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z $PID ]] && kill -9 ${PID} && rm -f ${PID_FILE}
		Read_config
		Del_iptables
		Save_iptables
		update-rc.d -f ocserv remove
		rm -rf /etc/init.d/ocserv
		rm -rf "${conf_file}"
		rm -rf "${log_file}"
		cd '/usr/local/bin' && rm -f occtl
		rm -f ocpasswd
		cd '/usr/local/bin' && rm -f ocserv-fw
		cd '/usr/local/sbin' && rm -f ocserv
		cd '/usr/local/share/man/man8' && rm -f ocserv.8
		rm -f ocpasswd.8
		rm -f occtl.8
		echo && echo "ocserv Uninstall!" && echo
	else
		echo && echo "Uninstallation has been canceled..." && echo
	fi
}
over(){
	update-rc.d -f ocserv remove
	rm -rf /etc/init.d/ocserv
	rm -rf "${conf_file}"
	rm -rf "${log_file}"
	cd '/usr/local/bin' && rm -f occtl
	rm -f ocpasswd
	cd '/usr/local/bin' && rm -f ocserv-fw
	cd '/usr/local/sbin' && rm -f ocserv
	cd '/usr/local/share/man/man8' && rm -f ocserv.8
	rm -f ocpasswd.8
	rm -f occtl.8
	echo && echo "The installation process is wrong, OcServ is uninstalled complete !" && echo
}
Add_iptables(){
	iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${set_tcp_port} -j ACCEPT
	iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${set_udp_port} -j ACCEPT
}
Del_iptables(){
	iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${tcp_port} -j ACCEPT
	iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${udp_port} -j ACCEPT
}
Save_iptables(){
	iptables-save > /etc/iptables.up.rules
}
Set_iptables(){
	echo -e "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	sysctl -p
	ifconfig_status=$(ifconfig)
	if [[ -z ${ifconfig_status} ]]; then
		echo -e "${Error} ifconfig Not Installed !"
		read -e -p "Please enter your network card name manually (under normal circumstances, the network card is named ETH0, Debian9 is ENS3, the latest version of CentOS Ubuntu may be ENPXSX (X represents numbers or letters), Openvz virtualization is as a venet0:*):" Network_card
		[[ -z "${Network_card}" ]] && echo "取消..." && exit 1
	else
		Network_card=$(ifconfig|grep "eth0")
		if [[ ! -z ${Network_card} ]]; then
			Network_card="eth0"
		else
			Network_card=$(ifconfig|grep "ens3")
			if [[ ! -z ${Network_card} ]]; then
				Network_card="ens3"
			else
				Network_card=$(ifconfig|grep "venet0")
				if [[ ! -z ${Network_card} ]]; then
					Network_card="venet0"
				else
					ifconfig
					read -e -p "The network card of this server is detected non -ETH0 \ ENS3 (Debian9) \ venet0 (Openvz) \ ENPXSX (the latest version of CentOS Ubuntu, X represents numbers or letters), please manually enter your network card name according to the network card information output above.:" Network_card
					[[ -z "${Network_card}" ]] && echo "Cancel..." && exit 1
				fi
			fi
		fi
	fi
	iptables -t nat -A POSTROUTING -o ${Network_card} -j MASQUERADE
	
	iptables-save > /etc/iptables.up.rules
	echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules' > /etc/network/if-pre-up.d/iptables
	chmod +x /etc/network/if-pre-up.d/iptables
}
Update_Shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/lllvcs/ocserv/master/ocserv.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1) && sh_new_type="github"
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} Unable to connect Github !" && exit 0
	if [[ -e "/etc/init.d/ocserv" ]]; then
		rm -rf /etc/init.d/ocserv
		Service_ocserv
	fi
	wget -N --no-check-certificate "https://raw.githubusercontent.com/lllvcs/ocserv/master/ocserv.sh" && chmod +x ocserv.sh
	echo -e "The script has been updated toNote: Because the update method is to directly cover the currently running script, there may be some errors below, just ignore iT meaning: Because the update method is to directly cover the currently running script, there may be some errors below, just ignore it)" && exit 0
}
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && echo -e "${Error} This script does not support the current system ${release} !" && exit 1
echo && echo -e " ocserv 一Key installation management script ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  
 ${Green_font_prefix}0.${Font_color_suffix} Upgrade script
————————————
 ${Green_font_prefix}1.${Font_color_suffix} Install ocserv
 ${Green_font_prefix}2.${Font_color_suffix} Uninstalled ocserv
————————————
 ${Green_font_prefix}3.${Font_color_suffix} start up ocserv
 ${Green_font_prefix}4.${Font_color_suffix} stop ocserv
 ${Green_font_prefix}5.${Font_color_suffix} Restart ocserv
————————————
 ${Green_font_prefix}6.${Font_color_suffix} Set account configuration
 ${Green_font_prefix}7.${Font_color_suffix} View configuration information
 ${Green_font_prefix}8.${Font_color_suffix} Modify the configuration file
 ${Green_font_prefix}9.${Font_color_suffix} View log information
————————————" && echo
if [[ -e ${file} ]]; then
	check_pid
	if [[ ! -z "${PID}" ]]; then
		echo -e " Current state: ${Green_font_prefix} Installed ${Font_color_suffix} and ${Green_font_prefix} Have started ${Font_color_suffix}"
	else
		echo -e " Current state: ${Green_font_prefix} Installed Pack ${Font_color_suffix} but ${Red_font_prefix} have not started ${Font_color_suffix}"
	fi
else
	echo -e " Current state: ${Red_font_prefix} Not Installed ${Font_color_suffix}"
fi
echo
read -e -p " Please key in numbers [0-9]:" num
case "$num" in
	0)
	Update_Shell
	;;
	1)
	Install_ocserv
	;;
	2)
	Uninstall_ocserv
	;;
	3)
	Start_ocserv
	;;
	4)
	Stop_ocserv
	;;
	5)
	Restart_ocserv
	;;
	6)
	Set_Pass
	;;
	7)
	View_Config
	;;
	8)
	Set_ocserv
	;;
	9)
	View_Log
	;;
	*)
	echo "Please enter the correct number [0-9]"
	;;
esac