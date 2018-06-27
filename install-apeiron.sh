#!/bin/bash

TMP_FOLDER=$(mktemp -d)
CONFIG_FILE="apeiron.conf"
DEFAULTUSER="apeiron-mn1"
DEFAULTPORT=46123
BINARY_NAME="apeirond"
BINARY_FILE="/usr/local/bin/$BINARY_NAME"
CLI_NAME="apeiron-cli"
CLI_FILE="/usr/local/bin/$CLI_NAME"
APEIRON_DAEMON_ZIP="https://github.com/apeironcoin/apeiron/releases/download/v1.1/apeiron-linux_v1.1.tar.gz"
GITHUB_REPO="https://github.com/apeironcoin/apeiron"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

function checks() 
{
  if [[ $(lsb_release -d) != *16.04* ]]; then
    echo -e "${RED}You are not running Ubuntu 16.04. Installation is cancelled.${NC}"
    exit 1
  fi

  if [[ $EUID -ne 0 ]]; then
     echo -e "${RED}$0 must be run as root.${NC}"
     exit 1
  fi

  if [ -n "$(pidof $BINARY_NAME)" ]; then
    read -e -p "$(echo -e The APEIRON daemon is already running.$YELLOW Do you want to add another master node? [Y/N] $NC)" NEW_NODE
    clear
  else
    NEW_NODE="new"
  fi
}

function prepare_system() 
{
  clear
  echo -e "Checking if swap space is required."
  PHYMEM=$(free -g | awk '/^Mem:/{print $2}')
  
  if [ "$PHYMEM" -lt "2" ]; then
    SWAP=$(swapon -s get 1 | awk '{print $1}')
    if [ -z "$SWAP" ]; then
      echo -e "${GREEN}Server is running without a swap file and has less than 2G of RAM, creating a 2G swap file.${NC}"
      dd if=/dev/zero of=/swapfile bs=1024 count=2M
      chmod 600 /swapfile
      mkswap /swapfile
      swapon -a /swapfile
    else
      echo -e "${GREEN}Swap file already exists.${NC}"
    fi
  else
    echo -e "${GREEN}Server running with at least 2G of RAM, no swap file needed.${NC}"
  fi
  
  echo -e "${GREEN}Updating package manager.${NC}"
  apt update
  
  echo -e "${GREEN}Upgrading existing packages, it may take some time to finish.${NC}"
  DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y -qq upgrade 
  
  echo -e "${GREEN}Installing all dependencies for the APEIRON coin master node, it may take some time to finish.${NC}"
  apt install -y software-properties-common
  apt-add-repository -y ppa:bitcoin/bitcoin
  apt update
  apt install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
    make software-properties-common build-essential libtool autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev \
    libboost-program-options-dev libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git wget curl libdb4.8-dev libdb4.8++-dev \
    bsdmainutils libminiupnpc-dev libgmp3-dev ufw pkg-config libevent-dev  libdb5.3++ unzip libzmq5 htop pwgen
  clear
  
  if [ "$?" -gt "0" ]; then
      echo -e "${RED}Not all of the required packages were installed correctly.\n"
      echo -e "Try to install them manually by running the following commands:${NC}\n"
      echo -e "apt update"
      echo -e "apt -y install software-properties-common"
      echo -e "apt-add-repository -y ppa:bitcoin/bitcoin"
      echo -e "apt update"
      echo -e "apt install -y make software-properties-common build-essential libtool autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev \
    libboost-program-options-dev libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git wget curl libdb4.8-dev libdb4.8++-dev \
    bsdmainutils libminiupnpc-dev libgmp3-dev ufw pkg-config libevent-dev  libdb5.3++ unzip libzmq5 htop pwgen"
   exit 1
  fi

  clear
}

function deploy_binary() 
{
  if [ -f $BINARY_FILE ]; then
    echo -e "${GREEN}Apeiron daemon binary file already exists, using binary from $BINARY_FILE.${NC}"
  else
    cd $TMP_FOLDER

    echo -e "${GREEN}Downloading $APEIRON_DAEMON_ZIP and deploying the Apeiron service.${NC}"
    wget $APEIRON_DAEMON_ZIP -O apeiron.zip >/dev/null 2>&1

    tar xvzf apeiron.zip >/dev/null 2>&1
    cp $BINARY_NAME $CLI_NAME /usr/local/bin/
    chmod +x $BINARY_FILE >/dev/null 2>&1
    chmod +x $CLI_FILE >/dev/null 2>&1
    cd

    rm -rf $TMP_FOLDER
  fi
}

function enable_firewall() 
{
  echo -e "${GREEN}Installing fail2ban and setting up firewall to allow access on port $DAEMONPORT.${NC}"

  apt install ufw -y >/dev/null 2>&1

  ufw disable >/dev/null 2>&1
  ufw allow $DAEMONPORT/tcp comment "Apeiron Masternode port" >/dev/null 2>&1
  ufw allow $[DAEMONPORT+1]/tcp comment "Apeiron Masernode RPC port" >/dev/null 2>&1
  
  ufw logging on >/dev/null 2>&1
  ufw default deny incoming >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1

  echo "y" | ufw enable >/dev/null 2>&1
  systemctl enable fail2ban >/dev/null 2>&1
  systemctl start fail2ban >/dev/null 2>&1
}

function add_daemon_service() 
{
  cat << EOF > /etc/systemd/system/$APEIRONUSER.service
[Unit]
Description=Apeiron deamon service
After=network.target
After=syslog.target
[Service]
Type=forking
User=$APEIRONUSER
Group=$APEIRONUSER
WorkingDirectory=$APEIRONFOLDER
ExecStart=$BINARY_FILE -datadir=$APEIRONFOLDER -conf=$APEIRONFOLDER/$CONFIG_FILE -daemon 
ExecStop=$CLI_FILE stop
Restart=always
RestartSec=3
PrivateTmp=true
TimeoutStopSec=60s
TimeoutStartSec=10s
StartLimitInterval=120s
StartLimitBurst=5
  
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  sleep 3

  echo -e "${GREEN}Starting the Apeiron service from $BINARY_FILE on port $DAEMONPORT.${NC}"
  systemctl start $APEIRONUSER.service >/dev/null 2>&1
  
  echo -e "${GREEN}Enabling the service to start on reboot.${NC}"
  systemctl enable $APEIRONUSER.service >/dev/null 2>&1

  if [[ -z $(pidof $BINARY_NAME) ]]; then
    echo -e "${RED}The Apeiron masternode service is not running${NC}. You should start by running the following commands as root:"
    echo "systemctl start $APEIRONUSER.service"
    echo "systemctl status $APEIRONUSER.service"
    echo "less /var/log/syslog"
    exit 1
  fi
}

function ask_port() 
{
  read -e -p "$(echo -e $YELLOW Enter a port to run the Apeiron service on: $NC)" -i $DEFAULTPORT DAEMONPORT
}

function ask_user() 
{  
  read -e -p "$(echo -e $YELLOW Enter a new username to run the Apeiron service as: $NC)" -i $DEFAULTUSER APEIRONUSER

  if [ -z "$(getent passwd $APEIRONUSER)" ]; then
    useradd -m $APEIRONUSER
    USERPASS=$(pwgen -s 12 1)
    echo "$APEIRONUSER:$USERPASS" | chpasswd

    APEIRONHOME=$(sudo -H -u $APEIRONUSER bash -c 'echo $HOME')
    APEIRONFOLDER="$APEIRONHOME/.apeiron"
        
    mkdir -p $APEIRONFOLDER
    chown -R $APEIRONUSER: $APEIRONFOLDER >/dev/null 2>&1
  else
    clear
    echo -e "${RED}User already exists. Please enter another username.${NC}"
    ask_user
  fi
}

function check_port() 
{
  declare -a PORTS

  PORTS=($(netstat -tnlp | awk '/LISTEN/ {print $4}' | awk -F":" '{print $NF}' | sort | uniq | tr '\r\n'  ' '))
  ask_port

  while [[ ${PORTS[@]} =~ $DAEMONPORT ]] || [[ ${PORTS[@]} =~ $[DAEMONPORT+1] ]]; do
    clear
    echo -e "${RED}Port in use, please choose another port:${NF}"
    ask_port
  done
}

function ask_ip() 
{
  declare -a NODE_IPS
  declare -a NODE_IPS_STR

  for ips in $(netstat -i | awk '!/Kernel|Iface|lo/ {print $1," "}')
  do
    ipv4=$(curl --interface $ips --connect-timeout 2 -s4 icanhazip.com)
    NODE_IPS+=($ipv4)
    NODE_IPS_STR+=("$(echo -e [IPv4] $ipv4)")

    ipv6=$(curl --interface $ips --connect-timeout 2 -s6 icanhazip.com)
    NODE_IPS+=($ipv6)
    NODE_IPS_STR+=("$(echo -e [IPv6] $ipv6)")
  done

  if [ ${#NODE_IPS[@]} -gt 1 ]
    then
      echo -e "${GREEN}More than one IP address found.${NC}"
      INDEX=0
      for ip in "${NODE_IPS_STR[@]}"
      do
        echo -e " ${YELLOW}[${INDEX}] $ip${NC}"
        let INDEX=${INDEX}+1
      done
      echo -e " ${YELLOW}Which IP address do you want to use? Type 0 to use the first IP, 1 for the second and so on ...${NC}"
      read -e choose_ip
      NODEIP=${NODE_IPS[$choose_ip]}
  else
    NODEIP=${NODE_IPS[0]}
  fi
}

function create_config() 
{
  RPCUSER=$(pwgen -s 8 1)
  RPCPASSWORD=$(pwgen -s 15 1)
  cat << EOF > $APEIRONFOLDER/$CONFIG_FILE
rpcuser=$RPCUSER
rpcpassword=$RPCPASSWORD
rpcallowip=127.0.0.1
rpcport=$[DAEMONPORT+1]
listen=1
server=1
daemon=1
staking=1
port=$DAEMONPORT
EOF
}

function create_key() 
{
  read -e -p "$(echo -e $YELLOW Paste your masternode private key. Leave it blank to generate a new private key.$NC)" APEIRONPRIVKEY

  if [[ -z "$APEIRONPRIVKEY" ]]; then
    sudo -u $APEIRONUSER $BINARY_FILE -datadir=$APEIRONFOLDER -conf=$APEIRONFOLDER/$CONFIG_FILE -daemon >/dev/null 2>&1
    sleep 5

    if [ -z "$(pidof $BINARY_NAME)" ]; then
    echo -e "${RED}Apeiron deamon couldn't start, could not generate a private key. Check /var/log/syslog for errors.${NC}"
    exit 1
    fi

    APEIRONPRIVKEY=$(sudo -u $APEIRONUSER $CLI_FILE -datadir=$APEIRONFOLDER -conf=$APEIRONFOLDER/$CONFIG_FILE masternode genkey) 
    sudo -u $APEIRONUSER $CLI_FILE -datadir=$APEIRONFOLDER -conf=$APEIRONFOLDER/$CONFIG_FILE stop >/dev/null 2>&1
    sleep 5
  fi
}

function update_config() 
{  
  cat << EOF >> $APEIRONFOLDER/$CONFIG_FILE
logtimestamps=1
maxconnections=256
masternode=1
externalip=$NODEIP
masternodeprivkey=$APEIRONPRIVKEY
EOF
  chown $APEIRONUSER: $APEIRONFOLDER/$CONFIG_FILE >/dev/null
}

function add_log_truncate()
{
  LOG_FILE="$APEIRONFOLDER/debug.log";

  mkdir ~/.xuma >/dev/null 2>&1
  cat << EOF >> $DATA_DIR/logrotate.conf
$DATA_DIR/*.log {
    rotate 4
    weekly
    compress
    missingok
    notifempty
}
EOF

  if ! crontab -l | grep "/home/$USER_NAME/logrotate.conf"; then
    (crontab -l ; echo "1 0 * * 1 /usr/sbin/logrotate $DATA_DIR/logrotate.conf --state $DATA_DIR/logrotate-state") | crontab -
  fi
}

function show_output() 
{
 echo
 echo -e "================================================================================================================================"
 echo
 echo -e "Your APEIRON coin master node is up and running." 
 echo -e " - it is running as user ${GREEN}$APEIRONUSER${NC} and it is listening on port ${GREEN}$DAEMONPORT${NC} at your VPS address ${GREEN}$NODEIP${NC}."
 echo -e " - the ${GREEN}$APEIRONUSER${NC} password is ${GREEN}$USERPASS${NC}"
 echo -e " - the APEIRON configuration file is located at ${GREEN}$APEIRONFOLDER/$CONFIG_FILE${NC}"
 echo -e " - the masternode privkey is ${GREEN}$APEIRONPRIVKEY${NC}"
 echo
 echo -e "You can manage your APEIRON service from the cmdline with the following commands:"
 echo -e " - ${GREEN}systemctl start $APEIRONUSER.service${NC} to start the service for the given user."
 echo -e " - ${GREEN}systemctl stop $APEIRONUSER.service${NC} to stop the service for the given user."
 echo -e " - ${GREEN}systemctl status $APEIRONUSER.service${NC} to see the service status for the given user."
 echo
 echo -e "The installed service is set to:"
 echo -e " - auto start when your VPS is rebooted."
 echo -e " - rotate your ${GREEN}$LOG_FILE${NC} file once per week and keep the last 4 weeks of logs."
 echo
 echo -e "You can find the masternode status when logged in as $APEIRONUSER using the command below:"
 echo -e " - ${GREEN}${CLI_BINARY}getinfo${NC} to retreive your nodes status and information"
 echo
 echo -e "  if you are not logged in as $APEIRONUSER then you can run ${YELLOW}su - $APEIRONUSER${NC} to switch to that user before"
 echo -e "  running the ${GREEN}getinfo${NC} command."
 echo -e "  NOTE: the ${BINARY_NAME} daemon must be running first before trying this command. See notes above on service commands usage."
 echo
 echo -e "================================================================================================================================"
 echo
}

function setup_node() 
{
  ask_user
  check_port
  ask_ip
  create_config
  create_key
  update_config
  enable_firewall
  add_daemon_service
  add_log_truncate
  show_output
}

clear

echo
echo -e "============================================================================================================="
echo -e "${GREEN}"
echo -e "                                    db    88\"\"Yb 888888 88 88\"\"Yb"
echo -e "                                   dPYb   88__dP 88__   88 88__dP"
echo -e "                                  dP__Yb  88\"\"\"  88\"\"   88 88\"Yb"  
echo -e "                                 dP\"\"\"\"Yb 88     888888 88 88  Yb" 
echo
echo                          
echo -e "${NC}"
echo -e "This script will automate the installation of your APEIRON coin masternode and server configuration by"
echo -e "performing the following steps:"
echo
echo -e " - Prepare your system with the required dependencies"
echo -e " - Obtain the latest Apeiron masternode files from the Apeiron GitHub repository"
echo -e " - Create a user and password to run the Apeiron masternode service"
echo -e " - Install the Apeiron masternode service under the new user [not root]"
echo -e " - Add DDoS protection using fail2ban"
echo -e " - Update the system firewall to only allow; the masternode ports and outgoing connections"
echo -e " - Rotate and archive the masternode logs to save disk space"
echo
echo -e "The script will output ${YELLOW}questions${NC}, ${GREEN}information${NC} and ${RED}errors${NC}"
echo -e "When finished the script will show a summary of what has been done."
echo
echo -e "Script created by click2install"
echo -e " - GitHub: https://github.com/click2install/apeironcoin"
echo -e " - Discord: click2install#9625"
echo -e " - APEIRON: AYFt8nujoqZudztmZXDghpP4JFobg8ssko"
echo 
echo -e "============================================================================================================="
echo
read -e -p "$(echo -e $YELLOW Do you want to continue? [Y/N] $NC)" CHOICE

if [[ ("$CHOICE" == "n" || "$CHOICE" == "N") ]]; then
  exit 1;
fi

checks

if [[ ("$NEW_NODE" == "y" || "$NEW_NODE" == "Y") ]]; then
  setup_node
  exit 0
elif [[ "$NEW_NODE" == "new" ]]; then
  prepare_system
  deploy_binary
  setup_node
else
  echo -e "${GREEN}APEIRON daemon already running.${NC}"
  exit 0
fi
