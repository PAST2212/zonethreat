import os
import time
import requests
import textdistance
import tldextract
import csv
import whois
from confusables import unconfuse
import dns.resolver
import unicodedata
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import pandas as pd
from colorama import Fore, Style
import sys

FG, BT, FR, FY, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Fore.YELLOW, Style.RESET_ALL

desktop = os.path.join(os.path.expanduser('~'), 'zonethreat')

deduplicated_domains = []

monitoring_results = []

whois_registrar_list = []

domain_status = []

# Strings or brand names to monitor
# e.g. brands or mailing domain names that your company is using for sending mails
# Keyword File as List
brandnames = []

# Important if there are common word collisions between brand names and other words to reduce false positives
# e.g. blacklist "lotto" if you monitor brand "otto"
# Blacklist File as List
blacklist = []


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
    'Pragma': 'no-cache', 'Cache-Control': 'no-cache'}


def damerau(keyword, domain):
    domain_name = tldextract.extract(domain).domain
    damerau = textdistance.damerau_levenshtein(keyword, domain_name)

    if 5 <= len(keyword) <= 9:
        if damerau <= 1:
            return domain

    elif len(keyword) >= 10:
        if damerau <= 2:
            return domain


# Using Token-based Textdistance Jaccard for finding look-a-like Domains
def jaccard(keyword, domain, n_gram):
    domain_letter_weight = '#' + tldextract.extract(domain).domain + '#'
    keyword_letter_weight = '#' + keyword + '#'
    ngram_keyword = [keyword_letter_weight[i:i + n_gram] for i in range(len(keyword_letter_weight) - n_gram + 1)]
    ngram_domain_name = [domain_letter_weight[i:i + n_gram] for i in range(len(domain_letter_weight) - n_gram + 1)]
    intersection = set(ngram_keyword).intersection(ngram_domain_name)
    union = set(ngram_keyword).union(ngram_domain_name)
    similarity = len(intersection) / len(union) if len(union) > 0 else 0

    if similarity > 0.6:
        return domain


def jaro_winkler(keyword, domain):
    domain_name = tldextract.extract(domain).domain
    Jaro_Winkler = textdistance.jaro_winkler.normalized_similarity(keyword, domain_name)
    if Jaro_Winkler >= 0.9:
        return domain


# Make Domain creation date lookup via WHOIS protocol.
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


# Make Domain registrar lookup via WHOIS protocol.
def whois_registrar(domain):
    hey = []
    hey.append(domain)
    try:
        registered = whois.whois(domain)
        registered_1 = registered.registrar.replace(',', '')
        time.sleep(0.5)
        hey.append(registered_1)
        return list(filter(None, hey))

    except:
        pass


# Read Keywords TXT File as List
def read_input_keywords_file():
    file_keywords = open(desktop + '/User Input/keywords.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_keywords:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
        if domain is not None and domain != '':
            brandnames.append(domain)
    file_keywords.close()


# Read Blacklist for Keywords TXT File as List
def read_input_blacklist_file():
    file_blacklist = open(desktop + '/User Input/blacklist_keywords.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_blacklist:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
        if domain is not None and domain != '':
            blacklist.append(domain)
    file_blacklist.close()


#Check for website status
def website_status(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    resolver.nameservers = ['8.8.8.8']
    try:
        ns_lookup = resolver.resolve(domain, 'NS')
        if ns_lookup:
            domains = 'http://' + domain
            request_session = requests.Session()
            request_session.keep_alive = False
            try:
                response = request_session.get(domains, headers=headers, allow_redirects=True, timeout=(5, 30))
                if response.raise_for_status() is None:
                    return domain_status.append((domain, 'Online'))

            except:
                return domain_status.append((domain, 'Offline'))

    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return domain_status.append((domain, 'Offline'))

    except (dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
        return domain_status.append((domain, 'Check for Status'))

    except:
        return domain_status.append((domain, 'Check for Status'))


def write_domain_monitoring_results_to_csv():
    with open(f'{desktop}/Registered-Domains from TLD-Zone-File_{zonefile}.csv', mode='a', newline='') as f:
        writer = csv.writer(f, delimiter=',')
        for k in monitoring_results:
            if isinstance(k, tuple):
                writer.writerow([k[0], k[1], k[2]])


def create_new_csv_file_domainresults():
    console_file_path = f'{desktop}/Registered-Domains from TLD-Zone-File_{zonefile}.csv'
    if not os.path.exists(console_file_path):
        header = ['Domains', 'Keyword Found', 'Detected By', 'Domain Registrar', 'Status Website']
        with open(console_file_path, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header)


def postprocessing_outputfile():
    df = pd.read_csv(f'{desktop}/Registered-Domains from TLD-Zone-File_{zonefile}.csv', delimiter=',')
    df.drop_duplicates(inplace=True, subset=['Domains'])
    df['Domain Registrar'] = df.apply(lambda x: registrar_to_csv(x['Domains']), axis=1)
    df['Status Website'] = df.apply(lambda x: status_to_csv(x['Domains']), axis=1)
    df.to_csv(f'{desktop}/Registered-Domains from TLD-Zone-File_{zonefile}.csv', index=False)


def preprocessing_inputfile():
    df = pd.read_csv(desktop + f'/Zonefile/{zonefile}.txt', delimiter='\t')
    df.drop(df.columns[1:], axis=1, inplace=True)
    df.drop_duplicates(inplace=True)
    df.to_csv(desktop + f'/Zonefile/{zonefile}.txt', index=False)


def read_input_zonefile():
    try:
        file_domain = open(desktop + f'/Zonefile/{zonefile}.txt', 'r', encoding='utf-8-sig')
        for my_domains in file_domain:
            domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip().rstrip('.')
            registered_domain = tldextract.extract(domain).registered_domain
            deduplicated_domains.append(registered_domain)
        file_domain.close()

    except Exception as e:
        print(f'Something went wrong with reading {zonefile}.txt Input File. Please check file name', e)
        sys.exit()


def fuzzyoperations(x, container1, container2, blacklist):
    index = x[0]  # index of sub list
    value = x[1]  # content of sub list
    results_temp = []
    print(FR + f'Processor Job {index} for domain monitoring is starting\n' + S)
    for domain in value:
        if domain[1] in domain[0] and all(black_keyword not in domain[0] for black_keyword in blacklist):
            results_temp.append((domain[0], domain[1], 'Full Word Match'))

        elif jaccard(domain[1], domain[0], n_gram=2) is not None:
            results_temp.append((domain[0], domain[1], 'Similarity Jaccard'))

        elif damerau(domain[1], domain[0]) is not None:
            results_temp.append((domain[0], domain[1], 'Similarity Damerau-Levenshtein'))

        elif jaro_winkler(domain[1], domain[0]) is not None:
            results_temp.append((domain[0], domain[1], 'Similarity Jaro-Winkler'))

        elif unconfuse(domain[0]) is not domain[0]:
            latin_domain = unicodedata.normalize('NFKD', unconfuse(domain[0])).encode('latin-1', 'ignore').decode(
                'latin-1')
            if domain[1] in latin_domain and all(black_keyword not in latin_domain for black_keyword in blacklist):
                results_temp.append((domain[0], domain[1], 'IDN Full Word Match'))

            elif damerau(domain[1], latin_domain) is not None:
                results_temp.append((domain[0], domain[1], 'IDN Similarity Damerau-Levenshtein'))

            elif jaccard(domain[1], latin_domain, n_gram=2) is not None:
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


def multithreading_status(n):
    thread_ex_list = [y[0] for y in monitoring_results if isinstance(y, tuple)]

    with ThreadPoolExecutor(n) as executor:
        executor.map(website_status, thread_ex_list)


def registrar_to_csv(input_data):
    for y in whois_registrar_list:
        if y[0] == input_data:
            return y[1]


def status_to_csv(input_data):
    for y in domain_status:
        if y[0] == input_data:
            return y[1]


if __name__ == '__main__':
    print('Please download zonefile you want to monitor from ICANN\n')
    print(f"Please extract downloaded .txt Domain Zone File to Standard Path {desktop}\n")
    zonefile = input('Type in Name of TLD Zone TXT-File you want to scan and press enter: ')
    print(f'Create Monitoring from Domain Zone File: "{zonefile}" in {desktop}/Zonefile')
    preprocessing_inputfile()
    read_input_keywords_file()
    read_input_blacklist_file()
    read_input_zonefile()
    create_new_csv_file_domainresults()

if __name__ == '__main__':
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

    processes = [multiprocessing.Process(target=fuzzyoperations, args=(sub, que_1, que_2, blacklist)) for sub in sub_list]

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
    print(t1 - t0, 'Seconds needed for Domainmonitoring')


if __name__ == '__main__':
    print(FR + 'Start Domain Registrar Lookups and check for Website Status\n' + S)
    multithreading_registrar(50)
    multithreading_status(50)
    postprocessing_outputfile()
    print(FG + 'End Domain Registrar Lookup Website Status checks\n' + S)
    print('Please check:', FY + f'{desktop}/Registered-Domains from TLD-Zone-File_.csv' + S, ' file for results\n')
