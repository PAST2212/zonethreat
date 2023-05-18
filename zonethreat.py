import os
import time
import textdistance
import tldextract
import csv
import whois
from confusables import unconfuse
import whoisit
import dns.resolver
import unicodedata
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import pandas as pd
from colorama import Fore, Style

FG, BT, FR, FY, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Fore.YELLOW, Style.RESET_ALL

whoisit.bootstrap(overrides=True)

desktop = os.path.join(os.path.expanduser('~'), 'zonethreat')

deduplicated_domains = []

monitoring_results = []

whois_registrar_list = []

domain_status = []

# Strings or brand names to monitor
# e.g. brands or mailing domain names that your company is using for sending mails
brandnames = ["tui", "tuitravel", "tuiairlines", "tuigroup", "tuicruises", "tuifrance"]

# Important if there are common word collisions between brand names and other words to reduce false positives
# e.g. blacklist "lotto" if you monitor brand "otto"
Blacklist = ["intuit", "tuition"]


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
    hey = []
    try:
        registered = whois.whois(domain)
        hey.append(domain)
        registered = registered.creation_date
        hey.append(registered[0].strftime('%d-%m-%y'))
        return list(filter(None, hey))

    except:
        pass



# Make Domain registrar lookup via WHOIS or RDAP protocol.
# Not activated per# default
def whois_registrar(domain):
    hey = []
    try:
        registered = whois.whois(domain)
        hey.append(domain)
        hey.append(str(registered.registrar).replace(',', ''))
        return list(filter(None, hey))

    except:
        pass


# Check for domain registration
def NXDOMAIN_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    try:
        resolver.resolve(domain, 'NS')
        return domain_status.append((domain, 'OK'))

    except dns.resolver.NXDOMAIN:
        return domain_status.append((domain, 'NXDOMAIN'))
        pass

    except:
        return domain_status.append((domain, 'NS lookup failed'))
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


def write_domain_monitoring_results_to_csv():
    with open(f'{desktop}/Registered-Domains from TLD-Zone-File_{zonefile}.csv', mode='a', newline='') as f:
        writer = csv.writer(f, delimiter=',')
        for k in monitoring_results:
            if isinstance(k, tuple):
                writer.writerow([k[0], k[1], k[2]])


def create_new_csv_file_domainresults():
    console_file_path = f'{desktop}/Registered-Domains from TLD-Zone-File_{zonefile}.csv'
    if not os.path.exists(console_file_path):
        print(f'Create Monitoring from Domain Zone File: {zonefile} in {desktop}')
        header = ['Domains', 'Keyword Found', 'Detected By', 'Domain Registrar', 'Registration Status']
        with open(console_file_path, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header)


def postprocessing_Outputfile():
    df = pd.read_csv(f'{desktop}/Registered-Domains from TLD-Zone-File_{zonefile}.csv', delimiter=',')
    df.drop_duplicates(inplace=True, subset=['Domains'])
    df['Domain Registrar'] = df.apply(lambda x: registrar_to_csv(x['Domains']), axis=1)
    df['Registration Status'] = df.apply(lambda x: status_to_csv(x['Domains']), axis=1)
    df = df.drop(df[df['Registration Status'] == 'NXDOMAIN'].index)
    df.to_csv(f'{desktop}/Registered-Domains from TLD-Zone-File_{zonefile}.csv', index=False)


def preprocessing_Inputfile():
    df = pd.read_csv(f'{desktop}/{zonefile}.txt', delimiter='\t')
    df.drop(df.columns[1:], axis=1, inplace=True)
    df.drop_duplicates(inplace=True)
    df.to_csv(f'{desktop}/{zonefile}.txt', index=False)


def read_input_deduplicated_domainfile():
    file_domain = open(f'{desktop}/{zonefile}.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_domain:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip().rstrip('.')
        deduplicated_domains.append(domain)
    file_domain.close()


def fuzzyoperations(x, container1, container2):
   index = x[0]   # index of sub list
   value = x[1]   # content of sub list
   results_temp = []
   print(FR + f'Processor Job {index} for domain monitoring is starting\n' + S)
   for domain in value:
       if domain[1] in domain[0] and all(black_keyword not in domain[0] for black_keyword in Blacklist):
           results_temp.append((domain[0], domain[1], 'Full Word Match'))

       elif jaccard(domain[1], domain[0]) is not None:
           results_temp.append((domain[0], domain[1], 'Similarity Jaccard'))

       elif damerau(domain[1], domain[0]) is not None:
           results_temp.append((domain[0], domain[1], 'Similarity Damerau-Levenshtein'))

       elif jaro_winkler(domain[1], domain[0]) is not None:
           results_temp.append((domain[0], domain[1], 'Similarity Jaro-Winkler'))

       elif unconfuse(domain[0]) is not domain[0]:
           latin_domain = unicodedata.normalize('NFKD', unconfuse(domain[0])).encode('latin-1', 'ignore').decode('latin-1')
           if domain[1] in latin_domain and all(black_keyword not in latin_domain for black_keyword in Blacklist):
               results_temp.append((domain[0], domain[1], 'IDN Full Word Match'))

           elif damerau(domain[1], latin_domain) is not None:
               results_temp.append((domain[0], domain[1], 'IDN Similarity Damerau-Levenshtein'))

           elif jaccard(domain[1], latin_domain) is not None:
               results_temp.append((domain[0], domain[1], 'IDN Similarity Jaccard'))

           elif jaro_winkler(domain[1], latin_domain) is not None:
               results_temp.append((domain[0], domain[1], 'IDN Similarity Jaro-Winkler'))

   container1.put(results_temp)
   container2.put(index)
   print(FG + f'Processor Job {index} for domain monitoring is finishing\n' + S)


def flatten(sublist):
    for i in sublist:
        if type(i) != type([1]):
            monitoring_results.append(i)
        else:
            flatten(i)


def multithreading_registrar(n):
    thread_ex_list = [y[0] for y in monitoring_results if isinstance(y, tuple)]

    with ThreadPoolExecutor(n) as executor:
        results = executor.map(whois_registrar, thread_ex_list)
        for result in results:
            if result is not None and len(result) > 1:
                whois_registrar_list.append(result)

    return whois_registrar_list


def multithreading_NXDOMAIN(n):
    thread_ex_list = [y[0] for y in monitoring_results if isinstance(y, tuple)]

    with ThreadPoolExecutor(n) as executor:
        executor.map(NXDOMAIN_record, thread_ex_list)


def registrar_to_csv(input_data):
    for y in whois_registrar_list:
        if y[0] == input_data:
            return y[1]


def status_to_csv(input_data):
    for y in domain_status:
        if y[0] == input_data:
            return y[1]


if __name__=='__main__':
    print('Please download zonefile you want to monitor from ICANN\n')
    print(f"Please extract downloaded .txt Domain Zone File to Standard Path {desktop}\n")
    zonefile = input('Type in Name of TLD Zone TXT-File you want to scan and press enter: ')
    preprocessing_Inputfile()
    read_input_deduplicated_domainfile()
    create_new_csv_file_domainresults()


if __name__=='__main__':
    t0 = time.time()
    print(FR + 'Start Domain Monitoring\n' + S)
    print('Start Domain Monitoring:', len(deduplicated_domains), 'Domains')

    new = [(x, y) for y in brandnames for x in deduplicated_domains]

    def split(domain_input_list, n):
        a, b = divmod(len(domain_input_list), n)
        split_domaininput = [domain_input_list[i * a + min(i, b):(i + 1) * a + min(i + 1, b)] for i in range(n)]
        split_domaininput_order = [[i, v] for i, v in enumerate(split_domaininput)]
        return split_domaininput_order


    sub_list = split(new, multiprocessing.cpu_count())
    print(multiprocessing.cpu_count(), 'CPU Units detected.')

    que_1 = multiprocessing.Queue()
    que_2 = multiprocessing.Queue()

    processes = [multiprocessing.Process(target=fuzzyoperations, args=(sub, que_1, que_2)) for sub in sub_list]

    for p in processes:
        p.daemon = True
        p.start()

    fuzzy_results_temp = [[que_1.get(), que_2.get()] for p in processes]

    for p in processes:
        p.join()
        p.close()

    flatten(fuzzy_results_temp)
    write_domain_monitoring_results_to_csv()
    print(FG + 'End Domain Monitoring\n' + S)
    t1 = time.time()
    print(t1-t0, 'Seconds needed for Domainmonitoring')


if __name__=='__main__':
    print(FR + 'Start Domain Registrar Lookups\n' + S)
    multithreading_registrar(50)
    multithreading_NXDOMAIN(50)
    postprocessing_Outputfile()
    print(FG + 'End Domain Registrar Lookup\n' + S)
    print('Please check:', FY + f'{desktop}/Registered-Domains from TLD-Zone-File_.csv' + S, ' file for results\n')
