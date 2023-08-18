# zonethreat
**Domain / TLD Zone File Monitoring for Brand and Mailing Domain Names**

**Current Version 2.1**

In opposite to my other projects which depends on newest data feed, here you can monitor directly in the domain zone files that are published by domain authorities (e.g. ICANN).

One advantage is to scan **millions over millions** of currently registered domains for one specific TLD at a time (e.g. .com / .net / .info, etc.) to find **brand impersonations**, **close cousins of confusingly similar looking domains** or using results for further data engineering / crime investigation operations.

![image](https://user-images.githubusercontent.com/124390875/219959254-7ad12944-f42f-4b2e-95e7-ca2741927d04.png)
Here I scan as an example all **registered 9.757.861 .info Domains** for brand or phishing domains in one batch.

# **Detection Scope**
- combo squatting (e.g. amazon-shop.com), 
- regular typo squatting cases (ammazon.com), 
- typical look-alikes / phishing / so called CEO-Fraud domains (e.g. arnazon.com (rn = m),
- and other forms of phishing websites / look-alike Domains (e.g. 𝗉ay𝞀al.com - greek letter RHO '𝞀' instead of latin letter 'p')

**Example Screenshot**

![image](https://github.com/PAST2212/zonethreat/assets/124390875/25120d1f-9f32-4b2f-9bcc-0ef0f00a854b)



# **Features:**
- Domain Registrar Feature; Abilitiy to differentiate between own registered domains and third party registered domains in case of consolidated (company) domain portfolio
- Website Status: Check if detected Website is online or not
- Multithreading (50 workers by defaul) & Multiprocessing
- False Positive Reduction Instruments (self defined Blacklists, Thresholds depending on string lenght).
- IDN / Homoglyph Detection.
- CSV Export
- Find domains that are identical or confusingly similar to your name/brand/mailing domain name/etc.
- Mix of Edit-based and Token-based textdistance algorithms to increase result quality.
- Possibility to change pre-defined thresholds of fuzzy-matching algorithms if you want to.


# **Instructions**

**How to install:**
- git clone https://github.com/PAST2212/zonethreat.git
- cd zonethreat
- pip install -r requirements.txt

**How to run:**
- python3 zonethreat.py

**How to update:**
- cd zonethreat
- git pull
- In case of a Merge Error: Try "git reset --hard" before "git pull"

**Before the first run - How it Works:**
1. Put your brand names or mailing domain names into this TXT file "User Input/keywords.txt" line per line for monitoring operations (without the TLD). Some "TUI" Names are listed per default.

2. Put common word collisions into this TXT file "User Input/blacklist_keywords.txt" line per line you want to exclude from the results to reduce false positives.
-  e.g. blacklist "lotto" if you monitor keyword "otto", e.g. blacklist "amazonas" if you want to monitor "amazon", e.g. blacklist "intuitive" if you want to monitor "tui" ...

3. Download / Extract your Domain Zone TXT File into the folder "Zonefile". A dummy and empty "info.txt" file is included. Delete this.

4. Run the script.

5. Type in the filename of file in folder "Zonefile" you want to scan (in this example "info" for .info domains in info.txt file).
![image](https://user-images.githubusercontent.com/124390875/219960853-0c7a058c-a3bb-47a4-bb4d-fd6ea677b47f.png)

**Necessary Condition:**
- Create a free account at https://czds.icann.org/home and request free access to the relevant TLDs / Domain Zone Files you want to scan (.com / .org / .net , etc.). Filetypes are .txt files
- Take another source (e.g. paid source) if you already have one


# **Changelog**
- Please see Changelog for Updates:
- https://github.com/PAST2212/zonethreat/blob/main/Changelog

# **Notes**

**Author**
- Patrick Steinhoff (https://www.linkedin.com/in/patrick-steinhoff-168892222/)

**TO DO**
- Activate Domain Creation Date as additional csv column
- API Integration from https://github.com/icann/czds-api-client-python and therefore scanning multiple TLD Zones at once
- Add Possibility to parse Arguments (e.g. workers for multithreading, e.g. add nameservers)
- Add Additional mechanisms to bypass WHOIS rate limits (e.g. RDAP protocol)

**Additional**
- written in python 3.7
- Added value in case of consolidated domain portfolios to find third party registered domains
