## Read Team vs Blue Team Engagement

This project was created to act as both, an attacker and a defender of a cyber attack.

As an attacker, gathering information about the systems is key.
Finding possible vulnerabilities, misconfigurations or anything that could allows to compromise the victim machine.

As a defender, looking at the logs, trying to determine how this attack was carried out.
Trying to determine what vulnerabilities were found, what the attacker had access to, what is the impact of the whole attack, and how to defend the systems from future attacks.

### Read Team

Enumeration

Using nmap to find all the devices on the network and what services are they running as well as trying to indentify the version and port of those services.

nmap -sV -sC -Pn 192.168.1.0/24



Once the nmap scan has finished we notice a machine running an Apache web server on port 80.
Taking a look at this we can see different directories.

Using dirbuster we can try to find other directories that might now be visible, while running the dirbuster scan, is a good idea to search those directories for more information.

Through checking some of the files in the directories manually, some possible usernames were found (Ashton, Hannah, Ryan), as well as the path to a secret directory "192.168.1.105/company_folder/secret_folder/"

Accessing the secret folder requires authentication.

Since Ashton is the person trying to access that folder, as found on the files availiable. 

A brute force attack on the username ashton using Hydra, might give us the password we need to access the secret folder.

