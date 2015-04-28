# Mimosa-Framework<br>
µMIMOSAWRITERROUTER - Abusing EPC on Cisco Router to collect data<br>

This is Mimosa Framework first release.<br>

Let me clarify some things here:<br>
<br>
1 - We are NOT exploiting a 0day on CISCO.<br>
2 - We know about other methods like GRE-Tunnels, Port Mirroring, lawful interception etc.<br>
3 - This is an automated tool to help PENTESTERS, in a controled enviroment, to collect intresting data.<br>
4 - This is really usefull for Threat Intelligence collection.<br>
5 - You have to get ENABLE privilege on the router to use Mimosa. :P<br>

python mimosa-cli.py<br>
Mimosa> help<br>

Documented commands (type help <topic>):<br>
========================================<br>
_load           ed       li              pause  set          start_capture<br>
_relative_load  edit     list            py     shell        stop_capture<br>
add_target      hi       list_targets    r      shortcuts<br>
cmdenvironment  history  load            run    show<br>
del_target      l        mimosa_options  save   show_target<br>
<br>
Undocumented commands:<br>
======================<br>
EOF  eof  exit  help  moo  q  quit<br>

Mimosa><br>


<b>Some shortcuts for PCAP Manual analisys using Tshark</b>
<br>
<b>List PCAP Protocols</b><br>
tshark -i2 -nqzio,phs -nlr pcapfile<br>

<b>Get URLS<br></b>
<br>
tshark -T fields -e http.host -e http.request.uri -Y 'http.request.method' -r pcapfile<br>
<br> 
<b>DNS Queries<br></b>
<br>
tshark -nn -e ip.src -e dns.qry.name  -T fields -Y "dns" -r pcapfile<br>
<br>
<b>FTP Creds<br></b>
<br>
tshark -Y "(ftp.response.code == 230 || ftp.request.command == "PASS") || (ftp.request.command == "USER")" -nlr pcapfile<br>
<br>
<b>POP Creds<br></b>
<br>
tshark -Y "(pop.request.command == "PASS") || (pop.request.command == "USER")" -nlr pcapfile <br>

<b>Cookies<br></b>
<br>
tshark -Y 'http.cookie' -z "proto,colinfo,http.content_type,http.content_type" -z "proto,colinfo,http.content_length,http.content_length" -z "proto,colinfo,http.cookie,http.cookie" -nlr pcapfile<br>

<b>HTTP REQUESTS<br></b>
<br>
tshark -T fields -e http.host -e http.request.uri -Y 'http.request.method == "GET"'  -nlr pcapfile<br>

<b>USER Agents<br></b>
<br>
tshark -Y 'http contains "User-Agent:"' -T fields -e http.user_agent -nlr pcapfile <br>

<b>HTTP Referer<br></b>
<br>
tshark -T fields -e http.host -e http.request.uri -Y 'http.referer' -nlr pcapfile<br>

<b>HTTP Location<br></b>
tshark -T fields -e http.host -e http.request.uri -Y 'http.location' -nlr pcapfile<br>






