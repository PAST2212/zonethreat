# zonethreat
**Domain / TLD Zone File Monitoring for Brand and Mailing Domain Names**

In opposite to my other projects which depends on newest data feed, here you can monitor directly in the domain zone files that are published by domain authorities (e.g. ICAAN).

The advantage is to scan **millions over millions** of currently registered domains for one specific TLD at a time (e.g. .com / .net / .info, etc.) to find **brand impersonations** or other **close cousins of confusingly similar looking domains**. 

![image](https://user-images.githubusercontent.com/124390875/219959254-7ad12944-f42f-4b2e-95e7-ca2741927d04.png)
Here i scan as an example all currently **registered 9.757.861 .info Domains** for brand or phishing domains. Please keep in mind that one scan operation could take several hours.

**Necessery Condition:**
- Create a free account at https://czds.icann.org/home and request free access to the relevant TLDs / Domain Zone Files you want to scan (.com / .org / .net , etc.)

**You can recognize:**
- combo squatting (e.g. amazon-shop.com), 
- typo squatting (ammazon.com), 
- brand impersonations, 
- phishing attacks (e.g. CEO-Fraud),
- and other forms of phishing websites / look-alike Domains (e.g. 𝗉ay𝞀al.com - greek letter RHO '𝞀' instead of latin letter 'p')

**Example Screenshot**

![image](https://user-images.githubusercontent.com/124390875/219959586-d78cbaac-20ae-4092-ae4e-b58ad1fdb19d.png)


**Features:**
- False Positive Reduction Instruments (e.g. self defined Blacklists, Thresholds depending on string lenght).
- IDN / Homoglyph Detection.
- CSV Export ("Ubuntu\home\User\Desktop" path is default path to create output).
- Find domains that are identical or confusingly similar to your name/brand/mailing domain name/etc.
- Mix of Edit-based and Token-based textdistance algorithms to increase result quality.
- Domain Registrar, Domain Creation Date, MX- and A-Record lookups are included but not activated by default.
- Possibility to change pre-defined thresholds of fuzzy-matching algorithms if you want to.

**How to install:**
- git clone https://github.com/PAST2212/zonehreat.git
- pip install -r requirements.txt

**How to run:**
- python3 zonethreat.py

**Before the first run - How it Works:**

![image](https://user-images.githubusercontent.com/124390875/216693263-1f4b68dd-ac95-4bda-8887-dba1044b3103.png)
Put your brands or mailing domain names into this list for monitoring operations (without the TLD).

![image](https://user-images.githubusercontent.com/124390875/216693388-b5543d15-26a0-410d-a62b-6e3764b713b6.png)
Put here common word collisions you want to exclude from the results to reduce false positives

**Authors**
- Patrick Steinhoff (https://www.linkedin.com/in/patrick-steinhoff-168892222/)

Written in Python 3.7

TO DO:
- Add more appropriate measures to make domain registrar and whois creation date lookups to give help for domain consolidation operations for specific TLDs / help to find companies forgotten domains
