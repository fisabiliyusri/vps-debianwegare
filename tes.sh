#!/bin/bash
#
# Original script by fornesia, rzengineer and fawzya 
# 
# ==================================================
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";
			
# update
echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable-wireguard.list && printf 'Package: *\nPin: release a=unstable\nPin-Priority: 150\n' > /etc/apt/preferences.d/limit-unstable && apt update && apt -y install linux-headers-$(uname -r|sed 's/[^-]*-[^-]*-//') && apt install wireguard -y && apt install -y openvpn openssl  && apt -y install wget curl && apt -y install nano dnsutils whois unzip && apt -y install squid && apt -y install dropbear && apt install stunnel4 -y && apt -y install fail2ban && apt -y install dnsutils dsniff && apt -y install libxml-parser-perl && apt -y install nginx && apt -y install neofetch && apt -y install php php-curl && apt -y install --no-install-recommends build-essential autoconf libtool libssl-dev libpcre3-dev libev-dev asciidoc xmlto automake git shadowsocks-libev qrencode && apt -y upgrade

# remove unused
apt -y --purge remove samba*;
#apt -y --purge remove apache2*;
apt -y --purge remove sendmail*;
apt -y --purge remove bind9*;

# detail nama perusahaan
country=ID
state=Subang
locality=JawaBarat
organization=wegassh
organizationalunit=wegassh
commonname=wegare.com
email=wega@gmail.com

# configure rc.local
cat <<EOF > /lib/systemd/system/rc-local.service
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
 
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
 
[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > /etc/rc.local
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.
badvpn-udpgw --listen-addr 127.0.0.1:7200 > /dev/nul &
badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/nul &
EOF
chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# add dns server ipv4
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf
sed -i '$ i\echo "nameserver 8.8.8.8" > /etc/resolv.conf' /etc/rc.local
sed -i '$ i\echo "nameserver 8.8.4.4" >> /etc/resolv.conf' /etc/rc.local

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# set repo
#echo 'deb http://download.webmin.com/download/repository sarge contrib' >> /etc/apt/sources.list.d/webmin.list
#wget "http://www.dotdeb.org/dotdeb.gpg"
#cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
#wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -

echo "clear" > .bashrc
echo 'echo -e ""' >> .bashrc
echo 'neofetch' >> .bashrc 
echo 'echo -e "welcome to the server $HOSTNAME"' >> .bashrc
echo 'echo -e "Script mod by Wegare"' >> .bashrc
echo 'echo -e "Type menu to display a list of commands"' >> .bashrc
echo 'echo -e ""' >> .bashrc

# install webserver
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/wegare123/vps-debian/main/nginx.conf"
mkdir -p /home/vps/public_html
echo "<pre>Setup by Wegare</pre>" > /home/vps/public_html/index.html
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/wegare123/vps-debian/main/vps.conf"

# install openvpn
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sysctl -p
#sett
group_name="nogroup"
protocol="udp"
protocol2="tcp"
port="1196"
port2="1194"
client="openvpn-udp"
client2="openvpn-tcp"
# Get easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	# Create the PKI, set up the CA and the server and client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
	chmod o+x /etc/openvpn/server/
	# Generate key for tls-crypt
	openvpn --genkey --secret /etc/openvpn/server/tc.key
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
# Generate server.conf
echo "port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
client-cert-not-required
username-as-common-name
plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.8.0.0 255.255.255.0" > /etc/openvpn/server/server.conf
echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
echo "keepalive 10 120
comp-lzo
persist-key
persist-tun
status server-udp.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf

echo "port $port2
proto $protocol2
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
client-cert-not-required
username-as-common-name
plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.9.0.0 255.255.255.0" > /etc/openvpn/server/server2.conf
echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server2.conf
echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server2.conf
echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server2.conf
echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server2.conf
echo "keepalive 10 120
comp-lzo
persist-key
persist-tun
status server-tcp.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server2.conf

	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	if [[ "$protocol2" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server2.conf
	fi
		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn@.service
	# client-common.txt is created so we have a template to add further users later
echo "client
dev tun
proto $protocol
remote $MYIP $port
route-method exe
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass
auth-nocache
comp-lzo
verb 3" > /etc/openvpn/server/client-common.txt
echo "client
dev tun
proto $protocol2
remote $MYIP $port2
route-method exe
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass
auth-nocache
comp-lzo
verb 3" > /etc/openvpn/server/client2-common.txt
	# Enable and start the OpenVPN service
	systemctl enable --now openvpn-server@server.service
	systemctl enable --now openvpn-server@server2.service
	# Generates the custom client.ovpn
	{
	cat /etc/openvpn/server/client-common.txt
	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	} > /home/vps/public_html/"$client".ovpn
	{
	cat /etc/openvpn/server/client2-common.txt
	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	} > /home/vps/public_html/"$client2".ovpn
	cd /home/vps/public_html/
	zip openvpn.zip openvpn-tcp.ovpn openvpn-udp.ovpn
	echo "selesai"

# install ss
porttls="8443"
porthttp="8444"
portssr="8445-8545"
git clone https://github.com/shadowsocks/simple-obfs.git
cd simple-obfs
git submodule update --init --recursive
./autogen.sh
./configure && make
make install
cd
rm -r simple-obfs
rm -r /etc/shadowsocks-libev/config.json

# install ssr
cd /etc/shadowsocks-libev/
wget -O ssr.zip "https://github.com/wegare123/vps-debian/blob/main/ssr.zip?raw=true"
unzip ssr.zip
rm -r ssr.zip

# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://github.com/wegare123/vps-debian/blob/main/badvpn-udpgw?raw=true"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://github.com/wegare123/vps-debian/blob/main/badvpn-udpgw64?raw=true"
fi
chmod +x /usr/bin/badvpn-udpgw
#sed -i '$ i\badvpn-udpgw --listen-addr 127.0.0.1:7200 > /dev/nul &' /etc/rc.local
#sed -i '$ i\badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/nul &' /etc/rc.local
badvpn-udpgw --listen-addr 127.0.0.1:7200 > /dev/nul &
badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/nul &

# setting port ssh
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config

# install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 80 -p 456"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/dropbear restart

# install squid
wget -O /etc/squid/squid.conf "https://raw.githubusercontent.com/wegare123/vps-debian/main/squid3.conf"
sed -i $MYIP2 /etc/squid/squid.conf;

# install stunnel
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 443
connect = 127.0.0.1:143

[openvpn]
accept = 992
connect = $MYIP:1194
END

# make a certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# configure stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart

# install ddos deflate
cd
wget -O ddos-deflate-master.zip "https://github.com/wegare123/vps-debian/blob/main/ddos-deflate-master.zip?raw=true"
unzip ddos-deflate-master.zip
cd ddos-deflate-master
yes | ./install.sh
rm -f /root/ddos-deflate-master.zip
cd
rm -r ddos-deflate-master

# banner /etc/bnr
wget -O /etc/banner.txt "https://raw.githubusercontent.com/wegare123/vps-debian/main/banner.txt"
sed -i 's@#Banner@Banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear

# install wg
portwg="7070"
    cat << EOF > /etc/wireguard/wg0.conf
[Interface]
Address = 10.7.0.0/24
PrivateKey = $(wg genkey)
ListenPort = $portwg
EOF
	chmod 600 /etc/wireguard/wg0.conf
	systemctl enable wg-quick@wg0

# iptables
NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
echo "iptables -t nat -I POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.9.0.0/24 -o $NIC -j MASQUERADE
iptables -t nat -I POSTROUTING 1 -s 10.7.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i wg0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o wg0 -j ACCEPT
iptables -I FORWARD 1 -i wg0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p udp --dport 7070 -j ACCEPT
iptables-save" >> /etc/rc.local

# download script
cd /usr/bin
wget -O menu "https://github.com/wegare123/vps-debian/blob/main/menu.sh?raw=true"
wget -O new "https://github.com/wegare123/vps-debian/blob/main/new.sh?raw=true"
wget -O port "https://github.com/wegare123/vps-debian/blob/main/port.sh?raw=true"
wget -O del "https://github.com/wegare123/vps-debian/blob/main/del.sh?raw=true"
wget -O cek "https://github.com/wegare123/vps-debian/blob/main/cek.sh?raw=true"
wget -O member "https://github.com/wegare123/vps-debian/blob/main/member.sh?raw=true"
wget -O speedtest "https://raw.githubusercontent.com/wegare123/vps-debian/main/speedtest_cli.py"
wget -O xp-wg "https://github.com/wegare123/vps-debian/blob/main/xp-wg.sh?raw=true"
wget -O add-wg "https://github.com/wegare123/vps-debian/blob/main/add-wg.sh?raw=true"
wget -O del-wg "https://github.com/wegare123/vps-debian/blob/main/del-wg.sh?raw=true"
wget -O add-pd "https://github.com/wegare123/vps-debian/blob/main/add-pd.sh?raw=true"
wget -O del-pd "https://github.com/wegare123/vps-debian/blob/main/del-pd.sh?raw=true"
wget -O xp-pd "https://github.com/wegare123/vps-debian/blob/main/xp-pd.sh?raw=true"
wget -O pointing.php "https://github.com/wegare123/vps-debian/blob/main/pointing.php?raw=true"
wget -O add-ss "https://github.com/wegare123/vps-debian/blob/main/add-ss.sh?raw=true"
wget -O del-ss "https://github.com/wegare123/vps-debian/blob/main/del-ss.sh?raw=true"
wget -O xp-ss "https://github.com/wegare123/vps-debian/blob/main/xp-ss.sh?raw=true"
wget -O run-ss "https://github.com/wegare123/vps-debian/blob/main/run-ss.sh?raw=true"
wget -O add-ssr "https://github.com/wegare123/vps-debian/blob/main/add-ssr.sh?raw=true"
wget -O del-ssr "https://github.com/wegare123/vps-debian/blob/main/del-ssr.sh?raw=true"
wget -O xp-ssr "https://github.com/wegare123/vps-debian/blob/main/xp-ssr.sh?raw=true"
wget -O run-ssr "https://github.com/wegare123/vps-debian/blob/main/run-ssr.sh?raw=true"

chmod +x run-ssr
chmod +x xp-ssr
chmod +x del-ssr
chmod +x add-ssr
chmod +x run-ss
chmod +x xp-ss
chmod +x del-ss
chmod +x add-ss
chmod +x xp-pd
chmod +x del-pd
chmod +x add-pd
chmod +x xp-wg
chmod +x add-wg
chmod +x del-wg
chmod +x menu
chmod +x port
chmod +x new
chmod +x del
chmod +x cek
chmod +x member
chmod +x speedtest

# finishing
cd
chown -R www-data:www-data /home/vps/public_html
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/cron restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
#/etc/init.d/webmin restart
/etc/init.d/stunnel4 restart
/etc/init.d/squid start
rm -rf ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# grep ports 
opensshport="$(netstat -ntlp | grep -i ssh | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
dropbearport="$(netstat -nlpt | grep -i dropbear | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
stunnel4port="$(netstat -nlpt | grep -i stunnel | grep -i 0.0.0.0 | awk '{print $4}' | head -n1 | cut -d: -f2)"
stunnel4port2="$(netstat -nlpt | grep -i stunnel | grep -i 0.0.0.0 | awk '{print $4}' | tail -n1 | cut -d: -f2)"
openvpnport="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
openvpnport2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
badvpn="$(netstat -nlpt | grep -i badvpn-udpgw | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
squidport="$(cat /etc/squid/squid.conf | grep -i http_port | awk '{print $2}')"
nginxport="$(netstat -nlpt | grep -i nginx| grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"

# install neofetch
#echo "deb http://dl.bintray.com/dawidd6/neofetch jessie main" | tee -a /etc/apt/sources.list
#curl "https://bintray.com/user/downloadSubjectPublicKey?username=bintray"| apt-key add -

# remove unnecessary files
apt -y autoremove
apt -y autoclean
apt -y clean

# info
clear
echo "Autoscript Include:" | tee log-install.txt
echo "===========================================" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Service"  | tee -a log-install.txt
echo "-------"  | tee -a log-install.txt
echo "OpenSSH : $opensshport"  | tee -a log-install.txt
echo "Dropbear : "$dropbearport | tr '\n' '\t'  | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "SSL : $stunnel4port"  | tee -a log-install.txt
echo "SS-Obfs-TLS : $porttls"  | tee -a log-install.txt
echo "SS-Obfs-HTTP : $porthttp"  | tee -a log-install.txt
echo "SSR : $portssr"  | tee -a log-install.txt
echo "WG : $portwg"  | tee -a log-install.txt
echo "Squid3   : "$squidport "(limit to IP SSH)" | tr '\n' '\t'  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "OpenVPN  : SSL $stunnel4port2"  | tee -a log-install.txt
echo "OpenVPN  : TCP $openvpnport (openvpn config : http://$MYIP:$nginxport/$client2.ovpn)"  | tee -a log-install.txt
echo "OpenVPN  : UDP $openvpnport2 (openvpn config : http://$MYIP:$nginxport/$client.ovpn)"  | tee -a log-install.txt
echo "OpenVPN  : ZIP (openvpn config : http://$MYIP:$nginxport/openvpn.zip)"  | tee -a log-install.txt
echo "badvpn   : badvpn-udpgw port "$badvpn | tr '\n' '\t'  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Script"  | tee -a log-install.txt
echo "------"  | tee -a log-install.txt
echo "menu (Displays a list of available commands)"  | tee -a log-install.txt
echo "new (Creating an SSH & OpenVPN Account)"  | tee -a log-install.txt
echo "del (Clearing SSH & OpenVPN Account)"  | tee -a log-install.txt
echo "cek (Check User Login SSH)"  | tee -a log-install.txt
echo "member (Check Member SSH & OpenVPN)"  | tee -a log-install.txt
echo "add-ss (Creating an SS-Obfs Account)"  | tee -a log-install.txt
echo "del-ss (Clearing SS-Obfs Account)"  | tee -a log-install.txt
echo "add-ss (Creating an SS-Obfs Account)"  | tee -a log-install.txt
echo "del-ss (Clearing SS-Obfs Account)"  | tee -a log-install.txt
echo "add-wg (Creating an WG Account)"  | tee -a log-install.txt
echo "del-wg (Clearing WG Account)"  | tee -a log-install.txt
echo "add-pd (Pointing Bug)"  | tee -a log-install.txt
echo "del-pd (Clearing Pointing Bug)"  | tee -a log-install.txt
echo "reboot (Reboot VPS)"  | tee -a log-install.txt
echo "speedtest (Speedtest VPS)"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Other features"  | tee -a log-install.txt
echo "----------"  | tee -a log-install.txt
echo "Timezone : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "IPv6     : [off]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Installation Log --> /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Mod by Wegare"  | tee -a log-install.txt
echo "Silahkan reboot!!!"  | tee -a log-install.txt
echo "==========================================="  | tee -a log-install.txt
cd
rm -f /root/install.sh
