#!/usr/bin/env python3

import json
import requests

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'  # white
Y = '\033[33m'  # yellow

found = []


def buffover(hostname):
    found = []
    print(Y + '[!]' + C + ' Requesting ' + G + 'BuffOver' + W)
    url = 'https://dns.bufferover.run/dns'
    bo_params = {
        'q': '{}'.format(hostname.split("/")[-1])
    }
    try:
        resp = requests.get(url, params=bo_params)
        sc = resp.status_code
        if sc == 200:
            output = resp.content
            json_out = json.loads(output)
            subds = json_out['FDNS_A']
            if subds == None:
                pass
            else:
                for subd in subds:
                    subd = subd.split(',')
                    for sub in subd:
                        found.append(sub)
        else:
            print(R + '[-]' + C + ' BuffOver Status : ' + W + str(sc))
    except Exception as e:
        print(R + '[-]' + C + ' BuffOver Exception : ' + W + str(e))
        pass
    return found


def subdomains(hostname):
    global found
    print(f'FOUND: {found}')
    result = {}

    print('\n' + Y + '[!]' + Y +
          ' Starting Sub-Domain Enumeration...' + W + '\n')

    buffover(hostname)

    valid = r"^[A-Za-z0-9._~()'!*:@,;+?-]*$"
    import re
    found = [item for item in found if re.match(valid, item)]
    found = set(found)
    total = len(found)

    if len(found) != 0:
        print('\n' + G + '[+]' + C + ' Results : ' + W + '\n')
        for url in found:
            print(G + '[+] ' + C + url)

    print('\n' + G + '[+]' + C +
          ' Total Unique Sub Domains Found : ' + W + str(total))

    result['Links'] = list(found)
    # subd_output(output, data, result, total)

    return subd_output(result, len(list(found)))


def subd_output(result, total):
    return {
        'module-Subdomain Enumeration': result,
        'Total Unique Sub Domains Found': str(total)
    }
