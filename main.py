from flask import Flask
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
from urllib.parse import urljoin, urlparse
import os
os.system
import requests
from bs4 import BeautifulSoup
# SSL
from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
from collections import namedtuple
import idna
import socket
import time
import argparse
import sys
import dateutil.parser
from datetime import datetime
import subprocess as sp
from monitoring import parse_whois_data, processcli, print_heading, DEBUG, debug, EXPIRE_STRINGS, REGISTRAR_STRINGS, \
    make_whois_query, calculate_expiration_days, check_expired, domain_expire_notify, print_domain
import whois

socket.getaddrinfo('localhost', 8080)
HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')
exporthttps_proxy = "http://<proxy.server>:<port>"

def get_subdomains():
    file = open('subdomain.txt', 'r')
    sub_dom = [line.rstrip() for line in file.readlines()]
    return sub_dom

# SSL
def verify_cert(cert, hostname):
    cert.has_expired()


def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((hostname, port))
        peername = sock.getpeername()
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE
        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        sock_ssl.do_handshake()
        cert = sock_ssl.get_peer_certificate()
        crypto_cert = cert.to_cryptography()
        sock_ssl.close()
        sock.close()
        return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

    except Exception as e:
        print("Exception %s" % e)


def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None


def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def print_basic_info(hostinfo):
    s = '''» {hostname} « … {peername}
    \tcommonName: {commonname}
    \tSAN: {SAN}
    \tissuer: {issuer}
    \tnotBefore: {notbefore}
    \tnotAfter:  {notafter}
    '''.format(
        hostname=hostinfo.hostname,
        peername=hostinfo.peername,
        commonname=get_common_name(hostinfo.cert),
        SAN=get_alt_names(hostinfo.cert),
        issuer=get_issuer(hostinfo.cert),
        notbefore=hostinfo.cert.not_valid_before,
        notafter=hostinfo.cert.not_valid_after
    )
    print(s)


def check_it_out(hostname, port):
    hostinfo = get_certificate(hostname, port)
    print_basic_info(hostinfo)


def get_certificate_details(domain):
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
        print_basic_info(get_certificate(domain, 443))


class MultiThreadedCrawler:
    def __init__(self, domain):
        self.seed_url = domain
        self.root_url = '{}://{}'.format(urlparse(self.seed_url).scheme,
                                         urlparse(self.seed_url).netloc)
        self.pool = ThreadPoolExecutor(max_workers=5)
        self.scraped_pages = set([])
        self.crawl_queue = Queue()
        self.crawl_queue.put(self.seed_url)

    def parse_links(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        Anchor_Tags = soup.find_all('a', href=True)
        for link in Anchor_Tags:
            url = link['href']
            if url.startswith('/') or url.startswith(self.root_url):
                url = urljoin(self.root_url, url)
                if url not in self.scraped_pages:
                    self.crawl_queue.put(url)

    def scrape_info(self, html):
        soup = BeautifulSoup(html, "html5lib")
        web_page_paragraph_contents = soup('p')
        text = ''
        for para in web_page_paragraph_contents:
            if not ('https:' in str(para.text)):
                text = text + str(para.text).strip()
        print(f'\n <---Text Present in The WebPage is --->\n', text, '\n')
        return

    def post_scrape_callback(self, res):
        result = res.result()
        if result and result.status_code == 200:
            self.parse_links(result.text)
            self.scrape_info(result.text)

    def scrape_page(self, url):
        try:
            res = requests.get(url, timeout=(3, 30))
            return res
        except requests.RequestException:
            return

    def scrap_sub_domaim(self, domain):
        sub_dom = get_subdomains()
        for subdomain in sub_dom:
            url = f"https://{subdomain}.{domain}"
            try:
                requests.get(url)
                print(f'{url}')
            except requests.ConnectionError:
                pass

    def get_response_sub_domain(self):
        try:
            print("Scraping URL: {}".format(self.current_scraping_url))
            self.scraped_pages.add(self.current_scraping_url)
            requests.get(self.current_scraping_url)
            return True
        except:
            return False

    def run_web_crawler(self):
        while True:
            try:
                print("\n Name of the current executing process: ",
                      multiprocessing.current_process().name, '\n')
                target_url = self.crawl_queue.get(timeout=60)
                if target_url not in self.scraped_pages:
                    for subdomain in get_subdomains():
                        self.current_scraping_url = "https://" + subdomain + '.' + target_url
                        if self.get_response_sub_domain():
                            print("Domain is a sub domain %s" % self.current_scraping_url)


            except Empty:
                return
            except Exception as e:
                print(e)
                continue

    def info(self):
        print('Seed URL is: ', self.seed_url, '\n')
        print('Scraped pages are: ', self.scraped_pages, '\n')


# HTTP_HTTPs

class http_status:
    def __init__(self, domain):
        if MultiThreadedCrawler.get_response_sub_domain(self):
            print("Ce site est en mode HTTP")
        else:
            print("Ce site est en mode HTTP et HTTPS")


# Date_Expiration
class DetailsDomain:
    EXPIRE_STRINGS = ["Registry Expiry Date:",
                      "Expiration:",
                      "Domain Expiration Date",
                      "Registrar Registration Expiration Date:",
                      "expire:",
                      "expires:",
                      "Expiry date"
                      ]

    REGISTRAR_STRINGS = [
        "Registrar:"
    ]

    DEBUG = 0

    def debug(self,string_to_print):
        if DEBUG:
            print(string_to_print)

    def print_domain(self, domain, registrar, expiration_date, days_remaining):
        print("%-25s  %-20s  %-30s  %-d" % (domain, registrar,
                                            expiration_date, days_remaining))

    def calculate_expiration_days(self, expiration_date):
        debug("Expiration date %s Time now %s" % (expiration_date, datetime.now()))
        try:
            domain_expire = expiration_date - datetime.now()
            return domain_expire.days
        except:
            return 0


    def make_whois_query(self, domain):
        debug("Sending a WHOIS query for the domain %s" % domain)
        try:
            return whois.whois(domain)

        except Exception as e:
            print("Unable to read from the Popen pipe. Exception %s" % e)
            sys.exit(1)

    def check_expired(self,expiration_days, days_remaining):

        if int(days_remaining) < int(expiration_days):
            return days_remaining
        else:
            return 0


    def print_info_domain(self, domain):
        whois_info = self.make_whois_query(domain)
        print("Domain Registrar: ", whois_info.registrar)
        print("Whois Server: ", whois_info.whois_server)
        print("Domain Creation Date: ", whois_info.creation_date)
        print("Expiration Date: ", whois_info.expiration_date)
        print("Remaining Days : ", self.calculate_expiration_days(whois_info.expiration_date))



if __name__ == '__main__':
    domain_to_search = input("Enter  the domain: ")
    get_certificate_details(domain_to_search)
    spider = MultiThreadedCrawler(domain=domain_to_search)
    spider.run_web_crawler()
    spider.info()
    http = http_status(domain=domain_to_search)
    print('\n')
    domain_details = DetailsDomain()
    domain_details.make_whois_query(domain=domain_to_search)
    domain_details.print_info_domain(domain_to_search)

