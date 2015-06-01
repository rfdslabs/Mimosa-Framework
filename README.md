# Mimosa-Framework
µMIMOSAWRITERROUTER - Abusing EPC on Cisco Router to collect data

This is Mimosa Framework first release.

![ScreenShot](http://i.imgur.com/ndV6CXZ.jpg) 


## Disclaimer

Some relevant points before about the project:

1. We are NOT exploiting a 0day on Cisco devices
2. We are aware of other methods, like GRE tunnels, port mirroring, lawful interception, etc.
3. This is an automated tool to help **pentesters** to collect interesting data in a **controled enviroment**
4. This is really useful tool for threat intelligence data gathering
5. You have to get **ENABLE** privilege on the router to use Mimosa

## Usage

```
$ python mimosa-cli.py
Mimosa> help

Documented commands (type help <topic>):
========================================
_load           ed       li              pause  set          start_capture
_relative_load  edit     list            py     shell        stop_capture
add_target      hi       list_targets    r      shortcuts
cmdenvironment  history  load            run    show
del_target      l        mimosa_options  save   show_target

Undocumented commands:
======================
EOF  eof  exit  help  moo  q  quit

Mimosa>
```

## Tips & Tricks

Some shortcuts for PCAP Manual analisys using Tshark

### List PCAP Protocols
```
tshark -i2 -nqzio,phs -nlr pcapfile
```

### Extract URLS
```
tshark -T fields -e http.host -e http.request.uri -Y 'http.request.method' -r pcapfile
```

### DNS Queries
```
tshark -nn -e ip.src -e dns.qry.name  -T fields -Y "dns" -r pcapfile
```

### FTP Credentials
```
tshark -Y \
  "(ftp.response.code == 230 || ftp.request.command == "PASS") || (ftp.request.command == "USER")" \
  -nlr pcapfile
```

### POP Credentials
```
tshark -Y \
  "(pop.request.command == "PASS") || (pop.request.command == "USER")" \
  -nlr pcapfile
```

### Cookies
```
tshark -Y 'http.cookie' \
  -z "proto,colinfo,http.content_type,http.content_type" \
  -z "proto,colinfo,http.content_length,http.content_length" \
  -z "proto,colinfo,http.cookie,http.cookie" -nlr pcapfile
```

### HTTP Requests
```
tshark -T fields -e http.host -e http.request.uri \
  -Y 'http.request.method == "GET"'  -nlr pcapfile
```

### User Agents
```
tshark -Y 'http contains "User-Agent:"' -T fields -e http.user_agent -nlr pcapfile
```

### HTTP Referer
```
tshark -T fields -e http.host -e http.request.uri -Y 'http.referer' -nlr pcapfile
```

### HTTP Location
```
tshark -T fields -e http.host -e http.request.uri -Y 'http.location' -nlr pcapfile
```





