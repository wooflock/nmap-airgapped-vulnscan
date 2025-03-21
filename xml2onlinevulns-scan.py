#!/bin/python

# script to use with nmap xml output from a system where you can not connect to the vulns database directly
# nmap -sV --script "vuln" [-p <port>] <ip>  ### needs internet... :-(
# do this:
# nmap -sV -oX output.xml [-p <port>] <ip>
# and feed the output.xml to this script on an internet computer.

import xml.etree.ElementTree as ET
import json
import argparse
import re
import urllib.request
import requests

def create_vulners_url(cpe_type,cpe_vendor,cpe_software,cpe_version):
    api_endpoint = "https://vulners.com/api/v3/burp/software/?"
    params1 = urllib.parse.urlencode( {'software': cpe_vendor + ":" +cpe_software, 'version': cpe_version, 'type': "cpe" } )
    params2 = urllib.parse.urlencode( {'software': cpe_software, 'version': cpe_version, 'type': "software" } )
    url1 = api_endpoint + params1
    url2 = api_endpoint + params2
    return [ url1, url2 ]

def handle_cpe(cpe):
    # takes a cpe 'cpe:/a:apache:http_server:2.4.49'
    # and breaks it down to an array of links to use with
    # the vulns service to as for CVEs
    cpe_pattern = r"cpe:/(a|o):([^:]+):([^:]+):([\d\.\-_]+)(?::([^:]*))?(?::([^:]*))?(?::([^:]*))?"
    match = re.search(cpe_pattern,cpe)
    if match:
        cpe_type = match.group(1)
        cpe_vendor = match.group(2)
        cpe_software = match.group(3)
        cpe_version = match.group(4)
        cpe_update = match.group(5) or "N/A"
        cpe_edition = match.group(6) or "N/A"
        cpe_language = match.group(7) or "N/A"

        # create a url for the vulners database
        cpe_urls = create_vulners_url(cpe_type, cpe_vendor, cpe_software, cpe_version)

        return {
            "cpe": { 
                "cpe": cpe,
                "breakdown_attempt": "success",    
                "cpe_type": cpe_type, 
                "cpe_vendor": cpe_vendor,
                "cpe_software": cpe_software,
                "cpe_version": cpe_version,
                "cpe_update": cpe_update,
                "cpe_edition": cpe_edition,
                "cpe_language": cpe_language,
                "cpe_urls": cpe_urls
            }
        }
    else:
        return { "cpe": { "cpe": cpe, "breakdown_attempt": "failure"}}

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    results = []
    
    for host in root.findall("host"):
        ip = host.find("address").get("addr") if host.find("address") is not None else "unknown"
        start_time = host.get("starttime", "unknown")
        end_time = host.get("endtime", "unknown")

        for port in host.findall(".//port"):
            port_num = port.get("portid")
            service = port.find(".//service")

            if service is not None:
                service_name = service.get("name", "unknown")
                service_version = service.get("version", "unknown")
                product = service.get("product", "unknown")
                cpes = [cpe.text for cpe in service.findall(".//cpe")]
                
                cpes = [handle_cpe(cpe) for cpe in cpes]

                results.append({
                    "starttime": start_time,
                    "endtime": end_time,
                    "ip": ip,
                    "port": port_num,
                    "service": service_name,
                    "product": product,
                    "version": service_version,
                    "cpe": cpes if cpes else None
                })

    return results


def insert_vuln_response(cpe, http_response ):
    for host_index in range(len(parsed_data)):
        for cpe_index in range(len(parsed_data[host_index]['cpe'])):
            if parsed_data[host_index]['cpe'][cpe_index]['cpe']['cpe'] == cpe:
                parsed_data[host_index]['cpe'][cpe_index]['cpe']['vulners_data'] = http_response

def query_vulners():
    # make sure we only ask once per cpe.
    vuln_cpe = {}

    for scan in parsed_data:
        for cpe in scan['cpe']:
            if "cpe_urls" in cpe['cpe']: 
                vuln_cpe[ cpe['cpe']['cpe'] ] = cpe['cpe']['cpe_urls']

    # now we have a unique list of cps and the 2 urls we created..
    # lets get them..
    http_headers = { 'User-Agent': 'Vulners NMAP Plugin 1.2' }
    for cpe in vuln_cpe:
        http_response = requests.get( vuln_cpe[cpe][0], headers=http_headers )         
        if http_response.status_code == 200:
            # the first url worked, lets save the result..
            insert_vuln_response(cpe, http_response.json())
        else: # ouch.. first url returned nothing, lets try to other..
            http_response = requests.get( vuln_cpe[cpe][1], headers=http_headers )
            if http_response.status_code == 200:
                # save the result.
                insert_vuln_response(cpe, http_response.json())

## main goes here.
parser = argparse.ArgumentParser(description="take a XML doc from nmap \"nmap -sV -oX <xml_file>\" konvert to JSON. and check online for vulns.")
parser.add_argument("-i", "--input", required=True, help="path for input xmlfil")
parser.add_argument("-o", "--output", help="path for output file")
parser.add_argument("-v", "--vulns", action="store_true", help="you wanna look it up agains the vulnsdatabase?")

args = parser.parse_args()

xmlfile = args.input
outfil = args.output
do_online = args.vulns

parsed_data = parse_nmap_xml(xmlfile)

if do_online:
    query_vulners()

if outfil:
    with open(outfil, "w") as of:
        json.dump(parsed_data, of, indent=4)

# create output to resemble nmap vulners.
# group per host.
host_ips = []
for ip in parsed_data:
    if ip['ip'] not in host_ips:
        host_ips.append(ip['ip'])

print("Starting Nmap playback info. ")

for ip in host_ips:
    print("Nmap scan report for " + ip)
    print("Host is up.")
    print()
    print("PORT    STATE  SERVICE  VERSION")

    # fetching info and matching ip for fetchd json
    for service in parsed_data:
        if service['ip'] == ip:
            port = service['port']
            service_name = service['service']
            product = service['product']
            version = service['version']
            print(port + " open " + service_name + "    " + product + " " + version)
            print("| vulners:")
            for cpe in service['cpe']:
                if not "vulners_data" in cpe['cpe']:
                    continue
                cpename = cpe['cpe']['cpe']
                print("|    " + cpename + ":")

                for vuln in cpe['cpe']['vulners_data']['data']['search']:
                    cvss_score = str(vuln['_source']['cvss']['score'])
                    family = vuln['_source']['bulletinFamily']
                    v_type = vuln['_source']['type']
                    print("|        " + vuln['id'] + "   " + cvss_score + "   https://vulners.com/" + v_type + "/" + vuln['id'] + "  " + family)

                print("")
