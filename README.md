## Read Team vs Blue Team Engagement

This project was created to act as both, an attacker and a defender of a cyber-attack.

As an attacker, gathering information about the systems is key. Finding possible vulnerabilities, misconfigurations or anything that could allow us to compromise the victim machine.

As a defender, looking at the logs, trying to determine how this attack was carried out and trying to determine what vulnerabilities were found, what the attacker had access to, what is the impact of the whole attack, and how to defend the systems from future attacks.
</br>
</br>
### Read Team

Using nmap to find all the devices on the network and what services are they running, as well as, trying to identify the version and port of those services.

`nmap -Ss -sV -oN nmap-scan.txt 192.168.1.0/24`
<p align="center">
<img src="https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-21%2017_56_05-Window.png"/>
<img src="https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-21%2017_57_14-Window.png"/>
</p> 
</br>
</br>
Once the nmap scan has finished we notice IP `192.168.1.105` is running an Apache server on port 80.
</br>
Opening this IP on the web browser takes us to what seems to be company directories.
<p align="center">
 <img src="https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-21%2018_01_53-Window.png"/>
</p>
</br> 
</br>

Looking around these directories we find really useful information like possible employee usernames. 
<p align="center">
 <img src="https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-21%2018_18_40-Window.png"/>
</p>
</br>
</br>
Due to poor configuration and lack of confidentiality we come across an interesting directory “/company_folders/secret_folder” 
<p align="center">
 <img src="https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-21%2018_11_57-Window.png"/>
 <img src="https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-21%2018_15_14-Window.png"/>
</p>
</br>
</br>
`Using dirbuster we can try to find other directories that might not be visible, we can leave that running in the background.`
</br>
</br>
Now that we have an interesting directory to look at, we can try accessing it.
<p align="center">
 <img src="https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-21%2018_28_32-Window.png"/>
</p>
</br>
</br>
Access to “secret_folder” requires authentication. From our information gathering stage we know Ashton is managing this directory, assuming his username is something like “ashton” we can try to brute force his password using Hydra.
<p align="center">
<img src="https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-23%2008_36_04-Red%20vs%20Blue%20(3)%20-%20ml-lab-9930d6c8-0122-48dc-8088-0fab0564893b.southcentralus.clo.png"/>
 </br>
<img sr="https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-23%2008_41_00-Red%20vs%20Blue%20(3)%20-%20ml-lab-9930d6c8-0122-48dc-8088-0fab0564893b.southcentralus.clo.png"/>
 </p>
</br>
</br>
After trying the credentials gathered from Hydra, we get access to the secret folder.
<p align="center">
 <img src"https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-23%2008_42_24-Window.png"/> 
</p>
</br>
</br>
There is a personal note containing more useful information. There is a MD5 hash for Ryan’s account and instruction on how to access a “webdav” directory.
<p align="center">
 <img src"(https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-23%2008_43_50-Window.png)"/> 
</p>
</br>
First let’s use `https://crackstation.net` to crack Ryan’s hash. We found a match for that hash, and the passwords is `inux4u`
<p align="center">
 <img src"(https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-23%2008_50_06-Window.png)"/> 
</p>

Taking a look at the instructions in the personal note, seems like they can be applied to our kali machine. 
`Going into Files > Other Locations > Under “Connect to Server” type dav://192.168.1.105/webdav/` this will prompt us to authenticate, in this case we know we are using Ryan’s account.

`Username: ryan`\
`Password: linux4u`

Now we are connected to the webdav server and there is one file in there. We can check if we can upload files to this server, if this is the case, then we can upload a reverse shell that would grant us access to that system.

Since we are able to upload files, let’s get a reverse shell into the webdav sever. Using a very simple php reverse shell found online, we modify the IP to direct to our kali machine and the port we want to use.
<p align="center">
 <img src"https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-24%2007_31_16-Window.png"/>
 <img src="https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-24%2007_33_29-Window.png"/>
</p>
</br>
</br>
By this time our `Dirbuster` scan is finished, but it didn't provide any extra information to what we have gathered so far.

[Dirbuster scan results](https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-23%2008_58_07-Window.png)

[Dirbuster scan results](https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-23%2008_58_20-Window.png)
</br>
</br>
Now that our reverse shell is in place, lets start a netcat listener running the following command:
`nc -lvnp 443`
<p align="center">
 <img src"https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-24%2007_36_04-Window.png"/> 
</p>
</br>
</br>
We can now navigate to the webdav server in our browser by going to `192.168.1.105/webdav` and this requires authentication again, so we use Ryan’s account one more time.
<p align="center">
 <img src"https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-24%2007_38_07-Window.png"/> 
</p>
</br>
</br>
We see our reverse shell is in place, all we need to do is run it. Nothing should happen on the web browser other than the page seems to never finish loading, but going back to our netcat listener we see our reverse shell connection has been stablished. We now have access to the system.
<p align="center">
 <img src"https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-24%2007_40_32-Window.png"/> 
</p>
</br>
</br>
Now we look for our flag, in this case it is in root directory in flag.txt file.
<p align="center">
 <img src"https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-24%2008_18_44-Window.png"/> 
</p>
</br> 
</br>
We could also upgrade the shell to get more functionality and switch to different users such as ryan and ashton.
This can be achieved by running the following command: `python -c 'import pty; pty.spawn("/bin/bash")'`
<p align="center">
 <img src"https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-24%2015_48_50-Red%20vs%20Blue%20-%20ml-lab-9930d6c8-0122-48dc-8088-0fab0564893b.southcentralus.cloudap.png"/> 
</p>
</br>
</br>
After poking around with different users nothing else seem to be of interest within their home directories. 

After looking around some more we can see this machine is running an unpatched version of sudo. This can be exploited by a heap buffer overflow vulnerability CVE-2021-3156, that could lead to privilege scalation.
<p align="center">
 <img src"https://github.com/gigsforfun/Red-vs-Blue-Project/blob/main/Red-Team/Images/2021-04-24%2016_02_10-Red%20vs%20Blue%20-%20ml-lab-9930d6c8-0122-48dc-8088-0fab0564893b.southcentralus.cloudap.png"/> 
</p>
</br>
</br>
</br>
###Blue Team

As part of the Blue Team, we are going to analyze all the logs during the time the system was attacked.
These logs were gathered using Elk Stack with metricbeat, filebeat and packetbeat installed on the victim machine (capstone).

Using Kibana we see the attack was carried out on 04/25/2021 at 14:17
Inspecting some of the traffic we see there are many port requests to many different ports. This indicates a possible nmap scan or similar tool. 
The attackers most likely found por 80 which is open, while doing the network scan.
Note: the search is set to ignore port 80 to have a clearer visualization of the rest of the ports scanned.
 

Taking a look at some of the HTTP traffic from our server, we see there are a lot of 404 errors indicating a tool such as gobuster or dirbuster was used to enumerate the web server directories.
There is also a high amount of 401 errors indicating a brute force attack.
 

Looking at the destination IP for these codes we find the possible attacker machine IP address, which is 192.168.1.8. 
Looking a little deeper into the HTTP response code 401, we find the tools the attackers used by looking at the user agent. We see Dirbuster and Hydra were used.
 

Following the Hydra trail, let’s find out what they were brute forcing.
 This shows the URL path was /company_folders/secret_folder/
 

 

Since the attacker accessed the secret_folder directory and Ashton’s personal note “connect_to_corp_server”, the attacker got a hold of Ryan’s credentials and was able to accessed the webdav server.
Looking at some HTTP requests data, we see a file called “shell.php” was requested from the webdav server. This file can be potentially malicious.
 

This could be a reverse shell, we can confirm this by going into the webdav folder and inspecting the shell.php, but if this was a real scenario the attacker would’ve most likely gotten rid of it.
Inside shell.php the connection back to the attacker’s machine is set to be made over 443
Notes: Trying to correlate the time the shell.php was requested with processes running at that same time (using metricbeat logs) did not bring any results that would indicate the file opens a reverse shell.
Checking filebeat syslogs for any process name that would lead to the reverse shell traffic didn’t provide any results either.
 





###Findings and Mitigations
The first step was doing some reconnaissance with Nmap. This type of scans can be difficult to detect if they are carried out slowly without making too much noise.
There are some configurations that can be made to prevent some scans, but it will not stop all of them.
•	Blocking ICMP so the machine does not respond to ping requests can be used, but it can be easily bypass by using the nmap flag -Pn. 
•	Also checking for a single IP trying to make multiple connections on different ports in a short amount of time, can be a way to identify a network a scan is happening, and an alert or trigger can be set up to stop this type of activity.
•	Keeping services up to date is also important, as well as, having only open ports that need to be open.

Then going through the web server directories, we were able to find valuable information that led us to a secret folder.
Some ways to prevent this could be:
•	Change the output message when a file is no longer available.
•	Train employees on confidentiality and privacy procedures.
•	An alert can be set in place to detect access to the hidden directory from any unknow IPs.

Once the secret folder was found we were able to brute force Ashton’s password. There are several ways to protect against this such as:
•	Require multi-factor authentication
•	Lock out users after certain amount of failed login attempts
•	Deploy a strong password policy.

After getting access to secret folder, we are able to see Ashton’s personal note on how to connect to the webdav server. Some of the mitigations for this could be:
•	Information like this shouldn’t be on a web server, specially not if it is only protected by a weak password. It can be kept locally, but it is still a bad practice to keep password in any files. Using a password manager to keep the notes and accounts credentials would’ve been a good option.
•	Ashton shouldn’t be using Ryan’s account, anyone that is authorized to use that server should have their own credentials for authentication.
•	An alert can be set in place to detect access to the webdav from any unknow IPs.
•	Monitor Uploads and set up client and server-side filtering.
•	All the uploads should be check by antivirus software.

