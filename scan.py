import math
import sys
import os
import json
import errno
import time
import socket
import maxminddb
import subprocess
import requests as req
from subprocess import TimeoutExpired




def broken_website(status_code):
    if status_code != 200 and status_code != 301 and status_code != 302:
        return True


def process_geolocation(ip_addresses):
    result = []
    with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
        for each in ip_addresses:
            #print(each)
            loc_dict = reader.get(each)
            #print(loc_dict)
            # print("location: ", loc_dict["location"])
            str = loc_dict["location"].get("time_zone").split("/")
            country = loc_dict["country"].get("names").get("en")
            res = str[1] + ", " + country
            if res not in result:
                result.append(res)
    return result

def get_domain_name(ip_addresses):
    result = []
    try:
        for each in ip_addresses:
            list = socket.gethostbyaddr(each)
            result.append(list[0])
    except socket.herror as exc:
        print("Unknown host")
    return result


def process_root_ca(key):
    cmd = ["openssl", "s_client", "-connect", key + ":443"]
    try:
        res = process_subprocess(cmd)
        for line in res.decode().split("\n"):
            if "i:O = " in line:
                #print("line: ", line)
                return line.split(",")[0].split("=")[1].strip()
    except Exception as caError:
        #print(caError)
        pass


def process_openssl(key):
    cmd = ["openssl", "s_client", "-tls1_3", "-connect", "tls13." + key + ":443"]
    return process_subprocess(cmd)


def process_nmap(key):
    cmd = ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", key]
    return process_subprocess(cmd)


def process_subprocess(cmd):
    try:
        result = subprocess.check_output(cmd, timeout=2, stderr=subprocess.STDOUT,shell=True)
    except subprocess.TimeoutExpired and subprocess.CalledProcessError as exc:
        #print("Command timed out: {}".format(exc))
        return None
    else:
        #print("result", result)
        return result


def process_tls_version(key):
    #import pdb
    try:
        result = process_nmap(key)
        res = []
        if "TLSv1.0:" in result.decode("utf-8"):
            res.append("TLSv1.0")
        if "TLSv1.1:" in result.decode("utf-8"):
            res.append("TLSv1.1")
        if "TLSv1.2:" in result.decode("utf-8"):
            res.append("TLSv1.2")
        if "SSLv2" in result.decode("utf-8"):
            res.append("SSLv2")
        if "SSLv3" in result.decode("utf-8"):
            res.append("SSLv3")
    except Exception as errorTLS:
        #print(errorTLS)
        pass

    try:
        open_ssl = process_openssl(key)
        #pdb.set_trace()
        if open_ssl is None:
            return res
        if "New, TLSv1.3" in open_ssl.decode():
            res.append("TLSv1.3")
    except TimeoutExpired as errorSSL:
        #print(errorSSL)
        pass
    return res


def process_hsts(link):
    try:
        req1 = req.get(link, timeout=3)
    except req.exceptions.SSLError and req.exceptions.ReadTimeout as error:
        #print("doesn't have SSL working properly (%s)")
        return False
    if 'strict-transport-security' in req1.headers:
        return True
    else:
        return False


def process_redirect_https(link, count):
    if count > 10:
        return link, False
    if link.startswith("https"):
        return link, True
    resp = req.head(link)
    # print("resp.headers", resp.headers)
    if "Location" not in resp.headers:
        return link, False
    if broken_website(resp.status_code):
        return link, False
    location = resp.headers['Location']
    # print("location redirected", location)
    return process_redirect_https(location, count + 1)


def process_http_server(link, key):
    resp = req.head(link)
    if "server" not in resp.headers:
        return None
    server = resp.headers['server']
    key = key.split(".")[0].capitalize()
    server += " (" + key + ")"
    return server


def process_nslookup(key, record_type):
    # get ipv4 address
    result = None
    try:
        result = subprocess.check_output(["nslookup", record_type, key, "8.8.8.8"],
                                         timeout=10, stderr=subprocess.STDOUT,shell=True).decode("utf-8")
    except subprocess.TimeoutExpired as exc:
        print("Command timed out: {}".format(exc))
        return []

    # print(result)
    parts = result.split("\n\n")
    #print(parts)
    addrs = []
    for part in parts:
        if "Non-authoritative" not in part:
            continue
        lines = part.split("\n")
        if record_type == "-type=A":
            for line in lines:
                if line.startswith("Address:"):
                    addrs.append(line.split(":")[1].strip())
        else:
            for line in lines:
                if "AAAA" in line:
                    addrs.append(line.split(" ")[3].strip())

    return addrs
def tcpConnection(ip,port):
    cmd = 'sh -c "time echo -e \'\\x1dclose\\x0d\' |timeout 2 telnet ' + ip + ' ' + port + '"'
    return connect(cmd)
def connect(cmd):
    try:
        result = subprocess.check_output(cmd, timeout=2, stderr=subprocess.STDOUT, shell=True)
        print("RTTresult", result)
        return result
    except subprocess.TimeoutExpired and subprocess.CalledProcessError as exc:
        #print("Command timed out: {}".format(exc))
        return None

def getRTT(ip,port,update=False):
    low = -99999999
    high = 99999999
    t = math.inf
    try:
        res = tcpConnection(ip,port).decode("utf-8")
        print("RTT "+res+"\n")
        if res is not None:
            for one in res.split("\n\n"):
                if "real" in one:
                    rtt = one.split("\n")[0].split("\t")[1].split("m")[1]
                    # to ms
                    t = float(rtt[:-1]) * 1000
                    return t
            return t
    except:
        if update is False:
            # 443 default
            for i in ["22","80"]:
                t = getRTT(ip,i, True)
                if t!=math.inf:
                    return t
        return None
def rangeRTT(websites):
    res = []
    for w in websites:
        one = getRTT(w,"443")
        if one:
            res.append(one)
    if len(res) == 0:
        return None
    if len(res) == 1:
        res.append(res[0])
        res.append(res[0])
    else:
        res.append(min(res))
        res.append(max(res))
    return res


def scaner_input_file(file_name, output):
    json_object = dict()
    if os.path.exists(file_name):
        f = open(file_name, "r")
        for each in f.readlines():
            each = each.strip()
            ipv4_addrs = process_nslookup(each, '-type=A')
            ipv6_addrs = process_nslookup(each, '-type=AAAA')
            server = process_http_server("http://" + each, each)
            link, redirect_to_https = process_redirect_https("http://" + each, 1)
            has_hsts = process_hsts(link)
            tls_version = process_tls_version(each)
            root_ca = process_root_ca(each)
            rTime = rangeRTT(ipv4_addrs)
            rdns_names = get_domain_name(ipv4_addrs)
            geo_locations = process_geolocation(ipv4_addrs)
            json_object[each] = {
                "scan_time": time.time(),
                "ipv4_addresses": ipv4_addrs,
                "ipv6_addresses": ipv6_addrs,
                "http_server": server,
                "insecure_http": False,
                "redirect_to_https": redirect_to_https,
                "hsts": has_hsts,
                "tls_versions": tls_version,
                "root_ca": root_ca,
                "rtt": rTime,
                "rdns_names": rdns_names,
                "geo_locations": geo_locations
            }

    with open(output, "w") as f:
        json.dump(json_object, f, sort_keys=True, indent=4)
    f.close()







if __name__ == '__main__':
    n = len(sys.argv)
    if n < 2:
        sys.stderr.write("Please type in input and output file")
        sys.exit(errno.EACCES)
    print(sys.argv)
    file_name = sys.argv[1]
    output = sys.argv[2]
    scaner_input_file(file_name, output)
    # check all kinds of command line
    # ipv6_addrs = process_nslookup("amazon.com", "-type=AAAA")
    # print(ipv6_addrs)
    # print("res: ", process_redirect_https("http://tripadvisor.com", 1))
    # print(has_hsts("https://tripadvisor.com"))
    # res = process_tls_version("cloudflare.com")
    # print("res: ", res)
    #print(process_root_ca("stevetarzia.com"))
    #print(get_domain_name(["142.250.191.110"]))
    #print(process_geolocation(["142.250.191.110"]))
