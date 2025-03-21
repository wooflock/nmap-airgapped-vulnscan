# nmap-airgapped-vulnscan
A small project for running vulners script functionality when no internet is available.

`nmap -sV --script vulners <range-of-ip>` is really nice but vulners needs access to the internet to check the cpes.
When penetrationtesting, or just vulnerability scanning your own internal networks you might not have access to the internet, due to the type of network your working on. For example airgapped networks, with no connection to the outside world, or tightly locked down networks that only allow certain traffic can not be scanned this way.

One way of solving the problem is to do a 2 stage rocket. And that is what i have done in this project.

On your tightly controlled internal network, run nmap like this:
`nmap -sV -oX <result.xml> <range-of-ips>`

For exampel if you are at a internal network at 192.168.100.0/24 and you want to save your scan in a file called scan.xml:
`nmap -sV -oX scan.xml 192.168.100.1-254`

When the scan is done, you copy result.xml to a USB stick and copy the file to an internet attached computer.
and run: 
`xml2onlinevulns-scan -i scan.xml -o scan.json -v`

The result will resemble the normal nmap scan, but you will also have a nice scan.json file with all the data from vulns at your fingertip.

```

$ python3 xml2onlinevulns-scan.py -i scan_results.xml -o kalle.json -v
Starting Nmap playback info. 
Nmap scan report for 192.168.100.97
Host is up.

PORT    STATE  SERVICE  VERSION
22 open ssh    OpenSSH 8.2p1 Ubuntu 4ubuntu0.4
| vulners:
|    cpe:/a:openbsd:openssh:8.2p1:
|        0221525F-07F5-5790-912D-F4B9E2D1B587   9.8   https://vulners.com/githubexploit/0221525F-07F5-5790-912D-F4B9E2D1B587  exploit
|        10213DBE-F683-58BB-B6D3-353173626207   6.8   https://vulners.com/githubexploit/10213DBE-F683-58BB-B6D3-353173626207  exploit
|        1337DAY-ID-26576   7.5   https://vulners.com/zdt/1337DAY-ID-26576  exploit
|        1337DAY-ID-39918   6.8   https://vulners.com/zdt/1337DAY-ID-39918  exploit
|        54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C   5.9   https://vulners.com/githubexploit/54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C  exploit
|        5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A   9.8   https://vulners.com/githubexploit/5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A  exploit
|        8AD01159-548E-546E-AA87-2DE89F3927EC   9.8   https://vulners.com/githubexploit/8AD01159-548E-546E-AA87-2DE89F3927EC  exploit
|        8FC9C5AB-3968-5F3C-825E-E8DB5379A623   9.8   https://vulners.com/githubexploit/8FC9C5AB-3968-5F3C-825E-E8DB5379A623  exploit
|        B8190CDB-3EB9-5631-9828-8064A1575B23   9.8   https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23  exploit
|        C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3   6.8   https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3  exploit
|        CVE-2016-20012   5.3   https://vulners.com/cve/CVE-2016-20012  cve
|        CVE-2020-12062   7.5   https://vulners.com/cve/CVE-2020-12062  cve
|        CVE-2020-14145   5.9   https://vulners.com/cve/CVE-2020-14145  cve
|        CVE-2020-15778   7.8   https://vulners.com/cve/CVE-2020-15778  cve
|        CVE-2021-28041   7.1   https://vulners.com/cve/CVE-2021-28041  cve
|        CVE-2021-36368   3.7   https://vulners.com/cve/CVE-2021-36368  cve
|        CVE-2021-41617   7.0   https://vulners.com/cve/CVE-2021-41617  cve
|        CVE-2023-38408   9.8   https://vulners.com/cve/CVE-2023-38408  cve
|        CVE-2023-48795   5.9   https://vulners.com/cve/CVE-2023-48795  cve
|        CVE-2023-51385   6.5   https://vulners.com/cve/CVE-2023-51385  cve
|        CVE-2025-26465   6.8   https://vulners.com/cve/CVE-2025-26465  cve
|        F0979183-AE88-53B4-86CF-3AF0523F3807   7.5   https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807  exploit
|        F79E574D-30C8-5C52-A801-66FFA0610BAA   6.8   https://vulners.com/githubexploit/F79E574D-30C8-5C52-A801-66FFA0610BAA  exploit
|        PACKETSTORM:140261   0.0   https://vulners.com/packetstorm/PACKETSTORM:140261  exploit
|        PACKETSTORM:173661   7.5   https://vulners.com/packetstorm/PACKETSTORM:173661  exploit
|        PACKETSTORM:189283   6.8   https://vulners.com/packetstorm/PACKETSTORM:189283  exploit
|        SSV:92579   7.5   https://vulners.com/seebug/SSV:92579  exploit

```
