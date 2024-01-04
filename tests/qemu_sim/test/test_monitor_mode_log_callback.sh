#!/bin/bash

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

source /opt/openenclave/share/openenclave/openenclaverc

echo "Switching to ./monitor_mode/open-enclave/log_callback/"
cd ./monitor_mode/open-enclave/log_callback/

IP_ADDRESS="192.168.1.100"
PORT="12001"
RPORT="12000"
CONFIG_FILE='./config.json'

while getopts "m:" opt; do
   case $opt in
    m)
      MODE=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Check the mode and execute the corresponding command
if [ "$MODE" == "server" ]; then
  echo "Executing as server ./popSGX_Monitor -m $MODE -c $CONFIG_FILE -p $RPORT -t $PORT"
  sudo ./popSGX_Monitor -m $MODE -c $CONFIG_FILE -p $RPORT -t $PORT
elif [ "$MODE" == "client" ]; then
  echo "Executing as client ./popSGX_Monitor -m $MODE -c $CONFIG_FILE -r $IP_ADDRESS -p $PORT -t $RPORT"
  sudo ./popSGX_Monitor -m $MODE -c $CONFIG_FILE -r $IP_ADDRESS -p $PORT -t $RPORT
else
  echo "Invalid mode. Use '-m server' or '-m client'."
  exit 1
fi	
