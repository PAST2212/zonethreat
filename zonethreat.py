import os
import time
import textdistance
import tldextract
import csv
import whois
from confusables import unconfuse
import whoisit
import re
import dns.resolver
import unicodedata
import pandas as pd

whoisit.bootstrap(overrides=True)

desktop = os.path.join(os.path.join(os.environ['HOME']), 'Desktop')

# Strings or brand names to monitor
# e.g. brands or mailing domain names that your company is using for sending mails
brandnames = ["tui", "tuitravel", "tuiairlines", "tuigroup", "tuicruises", "tuifrance"]

# Important if there are common word collisions between brand names and other words to reduce false positives
# e.g. blacklist "lotto" if you monitor brand "otto"
Blacklist = ["intuit", "tuition"]

print("Please extract downloaded .txt Domain Zone File to Standard Path Ubuntu/home/User/Desktop")
zonefile = input('Type in Name of TLD Zone TXT-File you want to scan and press enter: ')

def damerau(keyword, domain):
    domain_name = tldextract.extract(domain).domain
    damerau = textdistance.damerau_levenshtein(keyword, domain_name)
    if len(keyword) <= 3:
        pass

    elif 4 <= len(keyword) <= 9:
        if damerau <= 1:
            return domain
        else:
            pass

    elif len(keyword) >= 10:
        if damerau <= 2:
            return domain
        else:
            pass


def jaccard(keyword, domain):
    domain_name = tldextract.extract(domain).domain
    jaccard = textdistance.jaccard.normalized_similarity(keyword, domain_name)
    if jaccard >= 0.9:
        return domain
    else:
        pass


def jaro_winkler(keyword, domain):
    domain_name = tldextract.extract(domain).domain
    Jaro_Winkler = textdistance.jaro_winkler.normalized_similarity(keyword, domain_name)
    if Jaro_Winkler >= 0.9:
        return domain
    else:
        pass

# Make Domain creation date lookup via WHOIS or RDAP protocol.
# Not activated per default
def whois_creation_date(domain):
    import time
    try:
        registered = whoisit.domain(domain, allow_insecure_ssl=True)['registration_date']
        creation_date = registered.strftime('%d-%m-%y')
        return creation_date

    except (whoisit.errors.UnsupportedError, KeyError, AttributeError, whoisit.errors.QueryError):
        try:
            registered = whois.whois(domain)
            creation_date = registered.creation_date
            return creation_date[0].strftime('%d-%m-%y')

        except (TypeError, AttributeError):
            if creation_date is not None:
                return creation_date.strftime('%d-%m-%y')
            else:
                pass

        except Exception:
            pass
        except whois.parser.PywhoisError:
            pass

    except whoisit.errors.ResourceDoesNotExist:
        pass
    time.sleep(2)


# Make Domain registrar lookup via WHOIS or RDAP protocol.
# Not activated per# default
def whois_registrar(domain):
    import time
    try:
        registered = whoisit.domain(domain, allow_insecure_ssl=True)['entities']['registrar']
        registered_temp = list([registered[0].get('name')])
        registered_temp_2 = str(registered_temp).encode('utf-8-sig').decode('ascii', 'ignore')
        domain_registrar = re.sub(r"[\[,'\]]", "", str(registered_temp_2))
        return domain_registrar

    except (whoisit.errors.UnsupportedError, KeyError, AttributeError, whoisit.errors.QueryError, UnicodeError, UnicodeEncodeError, UnicodeDecodeError):
        try:
            registered = whois.whois(domain)
            domain_registrar = str(registered.registrar).replace(',', '')
            return domain_registrar

        except TypeError:
            pass
        except AttributeError:
            pass
        except Exception:
            pass
        except whois.parser.PywhoisError:
            pass

    except whoisit.errors.ResourceDoesNotExist:
            return 'NXDOMAIN'
            pass
    time.sleep(2)


# Make DNS MX-Record lookup.
# Not activated per default
def MX_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    try:
        MX = resolver.resolve(domain, 'MX')
        for answer in MX:
            return answer.exchange.to_text()[:-1]
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        return 'MX Record Not Found'
        pass
    except dns.name.EmptyLabel:
        pass
    except dns.resolver.Timeout:
        return 'Connection Timeout'
        pass
    except dns.exception.DNSException:
        pass


# Make DNS A-Record lookup.
# Not activated per default
def A_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    try:
        A = resolver.resolve(domain, 'A')
        for answer in A:
            return answer.address
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        return 'A Record Not Found'
        pass
    except dns.name.EmptyLabel:
        pass
    except dns.resolver.Timeout:
        return 'Connection Timeout'
        pass
    except dns.exception.DNSException:
        pass

console_file_path = f'{desktop}/Registered-Domains from TLD-Zone-File_{zonefile}.csv'
if not os.path.exists(console_file_path):
    print(f'Create Monitoring from Domain Zone File: {zonefile}')
    header = ['Domains', 'Keyword Found', 'Detected By']
    with open(console_file_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(header)

def processing_Outputfile():
    df = pd.read_csv(f'{desktop}/Registered-Domains from TLD-Zone-File_{zonefile}.csv', delimiter=',')
    df.drop_duplicates(inplace=True, subset=['Domains'])
    df['Domain Registrar'] = df.apply(lambda x: whois_registrar(x['Domains']), axis=1)
    df.to_csv(f'{desktop}/Registered-Domains from TLD-Zone-File_{zonefile}.csv', index=False)

def preprocessing_Inputfile():
    df = pd.read_csv(f'{desktop}/{zonefile}.txt', delimiter='\t')
    df.drop(df.columns[1:], axis=1, inplace=True)
    df.drop_duplicates(inplace=True)
    df.to_csv(f'{desktop}/{zonefile}.txt', index=False)

preprocessing_Inputfile()

file2 = open(f'{desktop}/{zonefile}.txt', 'r')
lines2 = file2.readlines()
print(f'Quantity of Registered and deduplicated Domains to be Scanned for Brand Impersonations and Similar looking Domains: ', len(lines2), f'.{zonefile} Domains')
file2.close()

time.sleep(3)

file1 = open(f'{desktop}/{zonefile}.txt', 'r', encoding='utf-8-sig')
while file1:
    lines = file1.readline()
    domain = lines.strip().rstrip('.')
    for keyword in brandnames:
        with open(f'{desktop}/Registered-Domains from TLD-Zone-File_{zonefile}.csv', mode='a', newline='') as f:
            writer = csv.writer(f, delimiter=',')
            if keyword in domain and all(black_keyword not in domain for black_keyword in Blacklist) is True:
                writer.writerow([domain, keyword, 'Full Word Match'])

            elif jaccard(keyword, domain) is not None:
                writer.writerow([domain, keyword, 'Jaccard'])

            elif damerau(keyword, domain) is not None:
                writer.writerow([domain, keyword, 'Damerau-Levenshtein'])

            elif jaro_winkler(keyword, domain) is not None:
                writer.writerow([domain, keyword, 'Jaro-Winkler'])

            elif unconfuse(domain) is not domain:
                latin_domain = unicodedata.normalize('NFKD', unconfuse(domain)).encode('latin-1', 'ignore').decode('latin-1')
                if keyword in latin_domain:
                    writer.writerow([domain, keyword, 'IDN Match'])
    if lines == '':
        break

time.sleep(3)

processing_Outputfile()
