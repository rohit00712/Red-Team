
# Red Team Recon

Learn how to use DNS, advanced searching, Recon-ng, and Maltego to collect information about your target.

The tasks of this room cover the following topics:

* Types of reconnaissance activities
* WHOIS and DNS-based reconnaissance
* Advanced searching
* Searching by image
* Google Hacking
* Specialized search engines
* Recon-ng
* Maltego

-------------------------------------------------------

## Built-in Tools

* `whois` to query the WHOIS database

`pentester@TryHackMe$ whois thmredteam.com`

In the following example, we can see whois provides us with:

* Registrar WHOIS server
* Registrar URL
* Record creation date
* Record update date
* Registrant contact info and address (unless withheld for privacy)
* Admin contact info and address (unless withheld for privacy)
* Tech contact info and address (unless withheld for privacy)

### 1.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

* `nslookup`, `dig`, or `host` to query DNS servers

DNS queries can be executed with many different tools found on our systems, especially Unix-like systems. One common tool found on Unix-like systems, Windows, and macOS is `nslookup`. In the following query, we can see how `nslookup` uses the default DNS server to get the A and AAAA records related to our domain.

`pentester@TryHackMe$ nslookup cafe.thmredteam.com`

### 2.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

Another tool commonly found on Unix-like systems is `dig`, short for Domain Information Groper (dig). `dig` provides a lot of query options and even allows you to specify a different DNS server to use. For example, we can use Cloudflare's DNS server: `dig @1.1.1.1 tryhackme.com`

`pentester@TryHackMe$ dig cafe.thmredteam.com @1.1.1.1`

### 3.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

`host` is another useful alternative for querying DNS servers for DNS records. Consider the following example.

### 4.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

#### Moreover, we can rely on Traceroute (traceroute on Linux and macOS systems and tracert on MS Windows systems) to discover the hops between our system and the target host.

`pentester@TryHackMe$ traceroute cafe.thmredteam.com`

-------------------------------------------------------

##  Advanced Searching

Being able to use a search engine efficiently is a crucial skill. The following table shows some popular search modifiers that work with many popular search engines.

| Symbol / Syntax | Function     | 
| :-------- | :------- | 
| "search phrase" | Find results with exact search phrase |
| OSINT filetype:pdf |	Find files of type PDF related to a certain term. |
| salary site:blog.tryhackme.com |	Limit search results to a specific site. |
| pentest -site:example.com |	Exclude a specific site from results |
| walkthrough intitle:TryHackMe |	Find pages with a specific term in the page title. |
| challenge inurl:tryhackme |	Find pages with a specific term in the page URL.

Note: In addition to `pdf`, other filetypes to consider are: `doc`, `docx`, `ppt`, `pptx`, `xls` and `xlsx`.

Some search engines, such as Google, provide a web interface for advanced searches: [Google Advanced Search](https://www.google.com/advanced_search). Other times, it is best to learn the syntax by heart, such as [Google Refine Web Searches](https://support.google.com/websearch/answer/2466433), [DuckDuckGo Search Syntax](https://help.duckduckgo.com/duckduckgo-help-pages/results/syntax/), and [Bing Advanced Search](https://help.bing.microsoft.com/apex/index/18/en-US/10002) Options.

Combining advanced Google searches with specific terms, documents containing sensitive information or vulnerable web servers can be found. Websites such as [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) (GHDB) collect such search terms and are publicly available. Let's take a look at some of the GHDB queries to see if our client has any confidential information exposed via search engines. GHDB contains queries under the following categories:

* `Footholds`
Consider GHDB-ID: 6364 as it uses the query `intitle:"index of" "nginx.log"` to discover Nginx logs and might reveal server misconfigurations that can be exploited.

* `Files Containing Usernames`
For example, GHDB-ID: 7047 uses the search term `intitle:"index of" "contacts.txt"` to discover files that leak juicy information.

* `Sensitive Directories`
For example, consider GHDB-ID: 6768, which uses the search term `inurl:/certs/server.key` to find out if a private RSA key is exposed.

* `Web Server Detection`
Consider GHDB-ID: 6876, which detects GlassFish Server information using the query `intitle:"GlassFish Server - Server Running"`.

* `Vulnerable Files`
For example, we can try to locate PHP files using the query `intitle:"index of" "*.php"`, as provided by GHDB-ID: 7786.

* `Vulnerable Servers`
For instance, to discover SolarWinds Orion web consoles, GHDB-ID: 6728 uses the query `intext:"user name" intext:"orion core" -solarwinds.com`.

* `Error Messages`
Plenty of useful information can be extracted from error messages. One example is GHDB-ID: 5963, which uses the query `intitle:"index of" errors.log` to find log files related to errors.

#### Now we'll explore two additional sources that can provide valuable information without interacting with our target:

* Social Media
* Job ads

**Note** that the Wayback Machine can be helpful to retrieve previous versions of a job opening page on your client’s site.

-------------------------------------------------------

## Specialized Search Engines

**WHOIS and DNS Related**

* [ViewDNS.info](https://viewdns.info/) : offers Reverse IP Lookup

### 5.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

* [Threat Intelligence Platform](https://threatintelligenceplatform.com/) :  requires you to provide a domain name or an IP address, and it will launch a series of tests from malware checks to WHOIS and DNS queries.

### 6.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

### Specialized Search Engines

* [Censys](https://search.censys.io/) : Censys Search can provide a lot of information about IP addresses and domains.

### 7.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

* [Shodan](https://cli.shodan.io/) : To use Shodan from the command-line properly, you need to create an account with Shodan, then configure `shodan` to use your API key using the command, `shodan init API_KEY`.

`shodan host IP_ADDRESS`

-------------------------------------------------------

## Recon-ng

Recon-ng is a framework that helps automate the OSINT work. It uses modules from various authors and provides a multitude of functionality. Some modules require keys to work; the key allows the module to query the related online API. In this task, we will demonstrate using Recon-ng in the terminal.

From a penetration testing and red team point of view, Recon-ng can be used to find various bits and pieces of information that can aid in an operation or OSINT task. All the data collected is automatically saved in the database related to your workspace. For instance, you might discover host addresses to later port-scan or collect contact email addresses for phishing attacks.






-------------------------------------------------------

## Maltego

Maltego is an application that blends mind-mapping with OSINT. In general, you would start with a domain name, company name, person’s name, email address, etc. Then you can let this piece of information go through various transforms.

The information collected in Maltego can be used for later stages. For instance, company information, contact names, and email addresses collected can be used to create very legitimate-looking phishing emails.


-------------------------------------------------------



## Screenshots

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)


## API Reference

#### Get all items

```http
  GET /api/items
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `api_key` | `string` | **Required**. Your API key |

#### Get item

```http
  GET /api/items/${id}
```

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `id`      | `string` | **Required**. Id of item to fetch |

#### add(num1, num2)

Takes two numbers and returns the sum.

