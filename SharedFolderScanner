import win32net
import win32netcon
import os
import sys
import ipaddress
import argparse
from multiprocessing.dummy import Pool as ThreadPool
import json


def write_file(filename, line):
    f = open(filename, "a+")
    f.write(line + "\n")
    f.close()


def ping(ip):
    result = 0
    cmd = "ping -n 1 " + str(ip)
    recv = os.popen(cmd).read()
    recv = recv.upper()

    if recv.count("TTL"):
        result = 1
        print ("ALIVE FOUND, %s" % ip)
    else:
        result = 0

    return (ip, result)


def pingParallel(IP_list, threads=2):
    pool = ThreadPool(threads)
    results = pool.map(ping, IP_list)
    pool.close()
    pool.join()
    return results


def scan_shared_holder_by_ip(ip):
    result = []

    COMPUTER_NAME = str(ip)
    INFO_LEVEL = 2

    try:
        shares, _, _ = win32net.NetShareEnum(COMPUTER_NAME, 0)
        all_shares = list(shares)

        for x in all_shares:
            result.append(x['netname'])

    except:
        result.append("ERROR")

    print (ip, result)

    return (ip, result)


def scanSharedFolderParallel(IP_list, threads=2):
    pool = ThreadPool(threads)
    results = pool.map(scan_shared_holder_by_ip, IP_list)
    pool.close()
    pool.join()
    return results


def get_all_ips_from_cidr(ip):
    ip = str(ip)

    if str(ip).count("/"):
        return list(ipaddress.ip_network(ip).hosts())
    else:
        return [ip]


if __name__ == "__main__":
    THREAD_COUNT = 6

    ALIVE_HOSTS =[]

    all_ips = get_all_ips_from_cidr(sys.argv[1])

    filename = sys.argv[1]
    filename = filename.replace("/", "_")
    filename = filename + "_output.txt"

    print("[*] Getting all alive IP addresses from (%s)" % sys.argv[1])

    results = pingParallel(all_ips, THREAD_COUNT)
    for n in results:
        if n[1] == 1:
            ALIVE_HOSTS.append(n[0])

    print ("")

    print("[*] Scanning all alive IP addresses for shared folder...")
    results = scanSharedFolderParallel(ALIVE_HOSTS, 2)

    for n in results:
        write_file(filename, str(n))

    print ("")
    print ("[Done!]")




