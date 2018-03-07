### proto_proxy_server

A test server to test proxy protocol data sanity

##### Build
```bash
make
```

#### Run
```bash
./pp_server 80
```
on success it will return  
```html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"> 
<html> 
  <head> 
    <title>400 Bad Request</title> 
  </head> 
  <body> 
    <h1>Proxy Protocol Report</h1> 
    <p> protocol version: v2 </p> 
    <p> address family: IPv4 </p> 
    <p>From: 192.168.0.136:0 -> To: 192.168.0.135:80 </p> 
  </body> 
</html>
```
And log on stderr (for V2)  
```bash
server established connection with host-192-168-0-134.openstacklocal (192.168.0.134)
proxy protocol v2

 Family: IPV4

From: 192.168.0.131:0  -> To: 192.168.0.135:80 
```
And it should not parse anything without proxy protocol and log  
```bash
server established connection with host-192-168-0-136.openstacklocal (192.168.0.136)
Failed to parse proxy protocol: -7
```
