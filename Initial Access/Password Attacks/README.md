
# Password Attacks

This room introduced the basic concepts of different password attacks and how to create custom and targeted password lists. We covered and discussed various topics, including:

* Default, weak, leaked combined wordlists
* Password profiling
* Offline password attacks
* Online password attacks

##  1. Password Profiling #1 - Default, Weak, Leaked, Combined , and Username Wordlists

### Default Passwords

Here are some website lists that provide default passwords for various products.

https://cirt.net/passwords

https://default-password.info/

https://datarecovery.com/rd/default-passwords/

### Weak Passwords

Here are some of the common weak passwords lists :

* https://wiki.skullsecurity.org/index.php?title=Passwords - This includes the most well-known collections of passwords.

* [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) - A huge collection of all kinds of lists, not only for password cracking.

### Leaked Passwords

* [SecLists/Passwords/Leaked-Databases](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases)

### Combined wordlists

Let's say that we have more than one wordlist. Then, we can combine these wordlists into one large file. This can be done as follows using cat:

`cat file1.txt file2.txt file3.txt > combined_list.txt`

To clean up the generated combined list to remove duplicated words, we can use sort and uniq as follows:

`sort combined_list.txt | uniq -u > cleaned_combined_list.txt`

### Customized Wordlists

Tools such as Cewl can be used to effectively crawl a website and extract strings or keywords. Cewl is a powerful tool to generate a wordlist specific to a given company or target. Consider the following example below:

` cewl -w list.txt -d 5 -m 5 http://thm.labs`

`-w` will write the contents to a file. In this case, list.txt.

`-m 5` gathers strings (words) that are 5 characters or more

`-d 5` is the depth level of web crawling/spidering (default 2)

`http://thm.labs` is the URL that will be used

### Username Wordlists

Gathering employees' names in the enumeration stage is essential. We can generate username lists from the target's website. For the following example, we'll assume we have a {first name} {last name} (ex: John Smith) and a method of generating usernames.

* {first name}: john
* {last name}: smith
* {first name}{last name}:  johnsmith 
* {last name}{first name}:  smithjohn  
* first letter of the {first name}{last name}: jsmith 
* first letter of the {last name}{first name}: sjohn  
* first letter of the {first name}.{last name}: j.smith 
* first letter of the {first name}-{last name}: j-smith 
* and so on

Thankfully, there is a tool `username_generator` that could help create a list with most of the possible combinations if we have a first name and last name.

`git clone https://github.com/therodri2/username_generator.git`

`cd username_generator`

`python3 username_generator.py -h` : For help

` echo "John Smith" > users.lst` : First create the wordlist that contain full name or names.

`python3 username_generator.py -w users.lst`

This is just one example of a custom username generator. Please feel free to explore more options or even create your own in the programming language of your choice!

-------------------------------------------------------

## 2. Password Profiling #2 - Keyspace Technique and CUPP

### Keyspace Technique :

`crunch` is one of many powerful tools for creating an offline wordlist. With `crunch`, we can specify numerous options, including min, max, and options as follows:

`crunch -h` : help menu

The following example creates a wordlist containing all possible combinations of 2 characters, including 0-4 and a-d. We can use the -o argument and specify a file to save the output to.

`crunch 2 2 01234abcd -o crunch.txt`

It's worth noting that crunch can generate a very large text file depending on the word length and combination options you specify. The following command creates a list with an 8 character minimum and maximum length containing numbers 0-9, a-f lowercase letters, and A-F uppercase letters:

`crunch 8 8 0123456789abcdefABCDEF -o crunch.txt` the file generated is `459 GB` and contains `54875873536 words`.

`crunch` also lets us specify a character set using the -t option to combine words of our choice. Here are some of the other options that could be used to help create different combinations of your choice:

`@` - lower case alpha characters

`,` - upper case alpha characters

`%` - numeric characters

`^` - special characters including space

For example, if part of the password is known to us, and we know it starts with `pass` and follows two numbers, we can use the % symbol from above to match the numbers. Here we generate a wordlist that contains `pass` followed by 2 numbers:

`crunch 6 6 -t pass%%`

### CUPP - Common User Passwords Profiler

CUPP is an automatic and interactive tool written in Python for creating custom wordlists. For instance, if you know some details about a specific target, such as their birthdate, pet name, company name, etc., this could be a helpful tool to generate passwords based on this known information.

CUPP will take the information supplied and generate a custom wordlist based on what's provided. There's also support for a 1337/leet mode, which substitutes the letters a, i,e, t, o, s, g, z  with numbers. For example, replace a  with 4  or i with 1. For more information about the tool, please visit the GitHub repo [here](https://github.com/Mebus/cupp).

To run CUPP, we need python 3 installed. Then clone the GitHub repo to your local machine using git as follows:

`git clone https://github.com/Mebus/cupp.git`

Now change the current directory to CUPP and run `python3 cupp.py` or with `-h` to see the available options.

`python3 cupp.py`

CUPP supports an interactive mode where it asks questions about the target and based on the provided answers, it creates a custom wordlist. If you don't have an answer for the given field, then skip it by pressing the `Enter` key.

` python3 cupp.py -i`

ِAs a result, a custom wordlist that contains various numbers of words based on your entries is generated. Pre-created wordlists can be downloaded to your machine as follows:

`python3 cupp.py -l`

Based on your interest, you can choose the wordlist from the list above to aid in generating wordlists for brute-forcing!

Finally, CUPP could also provide default usernames and passwords from the Alecto database by using the `-a` option.

`python3 cupp.py -a`

-------------------------------------------------------

## 3. Offline Attacks - Dictionary and Brute-Force

### Dictionary attack

Let's say that we obtain the following hash `f806fc5a2a0d5ba2471600758452799c`, and want to perform a dictionary attack to crack it. First, we need to know the following at a minimum:

1- What type of hash is this?

2- What wordlist will we be using? Or what type of attack mode could we use?

To identify the type of hash, we could a tool such as hashid or hash-identifier.

For this example, hash-identifier believed the possible hashing method is `MD5`

`hashcat -a 0 -m 0 f806fc5a2a0d5ba2471600758452799c /usr/share/wordlists/rockyou.txt`

`-a 0`  sets the attack mode to a dictionary attack

`-m 0`  sets the hash mode for cracking MD5 hashes; for other types, run hashcat -h for a list of supported hashes.

`f806fc5a2a0d5ba2471600758452799c` this option could be a single hash like our example or a file that contains a hash or multiple hashes.

`/usr/share/wordlists/rockyou.txt` the wordlist/dictionary file for our attack

We run `hashcat` with `--show` option to show the cracked value if the hash has been cracked:

` hashcat -a 0 -m 0 F806FC5A2A0D5BA2471600758452799C /usr/share/wordlists/rockyou.txt --show`

### Brute-Force attack

Brute-forcing is a common attack used by the attacker to gain unauthorized access to a personal account. This method is used to guess the victim's password by sending standard password combinations. The main difference between a dictionary and a brute-force attack is that a dictionary attack uses a wordlist that contains all possible passwords.

For instance, hashcat has charset options that could be used to generate your own combinations. The charsets can be found in hashcat help options.

`hashcat --help`

### 1.jpg

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

The following example shows how we can use hashcat with the brute-force attack mode with a combination of our choice. 

`hashcat -a 3 ?d?d?d?d --stdout`

`-a 3`  sets the attacking mode as a brute-force attack

`?d?d?d?d` the ?d tells hashcat to use a digit. In our case, ?d?d?d?d for four digits starting with 0000 and ending at 9999

`--stdout` print the result to the terminal

Now let's apply the same concept to crack the following MD5 hash: `05A5CF06982BA7892ED2A6D38FE832D6` a four-digit PIN number.

`hashcat -a 3 -m 0 05A5CF06982BA7892ED2A6D38FE832D6 ?d?d?d?d`

-------------------------------------------------------

## Offline Attacks - Rule-Based

Rule-Based attacks are also known as hybrid attacks. Rule-Based attacks assume the attacker knows something about the password policy. Rules are applied to create passwords within the guidelines of the given password policy and should, in theory, only generate valid passwords. Using pre-existing wordlists may be useful when generating passwords that fit a policy — for example, manipulating or 'mangling' a password such as 'password': `p@ssword`, `Pa$$word`, `Passw0rd`, and so on.

For this attack, we can expand our wordlist using either `hashcat` or `John the ripper`. However, for this attack, let's see how `John the ripper` works. Usually, `John the ripper` has a config file that contains rule sets, which is located at `/etc/john/john.conf` or `/opt/john/john.conf` depending on your distro or how john was installed. You can read `/etc/john/john.conf` and look for List.Rules to see all the available rules:

`cat /etc/john/john.conf|grep "List.Rules:" | cut -d"." -f3 | cut -d":" -f2 | cut -d"]" -f1 | awk NF`

### 2.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

We can see that we have many rules that are available for us to use. We will create a wordlist with only one password containing the string `tryhackme`, to see how we can expand the wordlist. Let's choose one of the rules, the best64 rule, which contains the `best 64` built-in John rules, and see what it can do!

`john --wordlist=/tmp/single-password-list.txt --rules=best64 --stdout | wc -l`

`--wordlist=` to specify the wordlist or dictionary file. 

`--rules` to specify which rule or rules to use.

`--stdout` to print the output to the terminal.

`|wc -l`  to count how many lines John produced.

By running the previous command, we expand our password list from 1 to 76 passwords. Now let's check another rule, one of the best rules in John, KoreLogic. KoreLogic uses various built-in and custom rules to generate complex password lists. For more information, please visit this website here. Now let's use this rule and check whether the `Tryh@ckm3` is available in our list!

`john --wordlist=single-password-list.txt --rules=KoreLogic --stdout |grep "Tryh@ckm3"`

The output from the previous command shows that our list has the complex version of tryhackme, which is Tryh@ckm3. Finally, we recommend checking out all the rules and finding one that works the best for you. Many rules apply combinations to an existing wordlist and expand the wordlist to increase the chance of finding a valid password!

### Custom Rules

`John the ripper` has a lot to offer. For instance, we can build our own rule(s) and use it at run time while john is cracking the hash or use the rule to build a custom wordlist!

Let's say we wanted to create a custom wordlist from a pre-existing dictionary with custom modification to the original dictionary. The goal is to add special characters (ex: !@#$*&) to the beginning of each word and add numbers 0-9 at the end. The format will be as follows:

`[symbols]word[0-9]`

We can add our rule to the end of john.conf:

```
user@machine$ sudo vi /etc/john/john.conf 
[List.Rules:THM-Password-Attacks] 
Az"[0-9]" ^[!@#$]
```
`[List.Rules:THM-Password-Attacks]`  specify the rule name THM-Password-Attacks.

`Az` represents a `single word` from the original wordlist/dictionary using `-p`.

`"[0-9]"` append a single digit (from 0 to 9) to the end of the word. For two digits, we can add `"[0-9][0-9]"`  and so on.  

`^[!@#$]` add a special character at the beginning of each word. `^` means the beginning of the line/word. Note, changing `^` to `$` will append the special characters to the end of the line/word.

Now let's create a file containing a single word `password` to see how we can expand our wordlist using this rule.

`echo "password" > /tmp/single.lst`

We include the name of the rule we created in the John command using the `--rules` option. We also need to show the result in the terminal. We can do this by using `--stdout` as follows:

`john --wordlist=/tmp/single.lst --rules=THM-Password-Attacks --stdout `

### 3.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

-------------------------------------------------------

## Online password attacks

Online password attacks involve guessing passwords for networked services that use a username and password authentication scheme, including services such as HTTP, SSH, VNC, FTP, SNMP, POP3, etc. This section showcases using `hydra` which is a common tool used in attacking logins for various network services.

### FTP

`hydra -l ftp -P passlist.txt ftp://10.10.x.x`

`-l ftp` we are specifying a single username, use-L for a username wordlist

`-P Path` specifying the full path of wordlist, you can specify a single password by using -p.

`ftp://10.10.x.x` the protocol and the IP address or the fully qualified domain name (FDQN) of the target.

Remember that sometimes you don't need to brute-force and could first try default credentials.

### SMTP

`hydra -l email@company.xyz -P /path/to/wordlist.txt smtp://10.10.x.x -v `

### SSH

`hydra -L users.lst -P /path/to/wordlist.txt ssh://10.10.x.x -v`

### HTTP login pages

In this scenario, we will brute-force `HTTP login pages`. To do that, first, you need to understand what you are brute-forcing. Using hydra, it is important to specify the type of HTTP request, whether `GET` or `POST`. Checking hydra options: `hydra http-get-form -U`, we can see that hydra has the following syntax for the `http-get-form` option:

`<url>:<form parameters>:<condition string>[:<optional>[:<optional>]`

As we mentioned earlier, we need to analyze the HTTP request that we need to send, and that could be done either by using your browser dev tools or using a web proxy such as Burp Suite.

`user@machine$ hydra -l admin -P 500-worst-passwords.txt 10.10.x.x http-get-form "/login-get/index.php:username=^USER^&password=^PASS^:S=logout.php" -f `

### 4.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

`-l admin`  we are specifying a single username, use-L for a username wordlist

`-P Path` specifying the full path of wordlist, you can specify a single password by using -p.

`10.10.x.x` the IP address or the fully qualified domain name (FQDN) of the target.

`http-get-form` the type of HTTP request, which can be either http-get-form or http-post-form.

Next, we specify the URL, path, and conditions that are split using :

`login-get/index.php` the path of the login page on the target webserver.

`username=^USER^&password=^PASS^` the parameters to brute-force, we inject ^USER^ to brute force usernames and ^PASS^ for passwords from the specified dictionary.

The following section is important to eliminate false positives by specifying the 'failed' condition with `F=`.

And success conditions, `S=`. You will have more information about these conditions by analyzing the webpage or in the enumeration stage! What you set for these values depends on the response you receive back from the server for a failed login attempt and a successful login attempt. For example, if you receive a message on the webpage 'Invalid password' after a failed login, set `F=Invalid Password`.

Or for example, during the enumeration, we found that the webserver serves `logout.php`. After logging into the login page with valid credentials, we could guess that we will have `logout.php` somewhere on the page. Therefore, we could tell hydra to look for the text `logout.php` within the HTML for every request.

`S=`logout.php the success condition to identify the valid credentials

`-f` to stop the brute-forcing attacks after finding a valid username and password

Finally, it is worth it to check other online password attacks tools to expand your knowledge, such as:

* Medusa
* Ncrack
* others!

-------------------------------------------------------

## Password spray attack

Password Spraying is an effective technique used to identify valid credentials. Nowadays, password spraying is considered one of the common password attacks for discovering weak passwords. This technique can be used against various online services and authentication systems, such as SSH, SMB, RDP, SMTP, Outlook Web Application, etc. A brute-force attack targets a specific username to try many weak and predictable passwords. While a password spraying attack targets many usernames using one common weak password, which could help avoid an account lockout policy. The following figure explains the concept of password spraying attacks where the attacker utilizes one common password against multiple users.

### 5.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)


### SSH

`hydra -L usernames-list.txt -p Spring2021 ssh://10.1.1.10`

### RDP

Tool : [RDPassSpray](https://github.com/xFreed0m/RDPassSpray)

`python3 RDPassSpray.py -h`

Now, let's try using the (-u) option to specify the `victim` as a username and the (-p) option set the `Spring2021!`. The (-t) option is to select a single host to attack.

`python3 RDPassSpray.py -u victim -p Spring2021! -t 10.100.10.240:3026`

Note that we can specify a domain name using the `-d` option if we are in an Active Directory environment.

`python3 RDPassSpray.py -U usernames-list.txt -p Spring2021! -d THM-labs -T RDP_servers.txt`

There are various tools that perform a spraying password attack against different services, such as:

### Outlook web access (OWA) portal
Tools:

* SprayingToolkit (atomizer.py)
* MailSniper

### SMB

Tool: `Metasploit (auxiliary/scanner/smb/smb_login)`















