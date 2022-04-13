""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, datetime, time
from connectors.core.connector import get_logger, ConnectorError

try:
    from integrations.crudhub import trigger_ingest_playbook
except:
    # ignore. lower FSR version
    pass

logger = get_logger('brute-force-blocker-feed')

errors = {
    400: 'Bad/Invalid Request',
    401: 'Unauthorized: Invalid credentials provided failed to authorize',
    403: 'Access Denied',
    404: 'Not Found',
    500: 'Internal Server Error'
}

SERVICE = {
    "BruteForceBlocker IPs Blocklist": "https://danger.rulez.sk/projects/bruteforceblocker/blist.php"
}


class BruteForceBlockerFeed(object):
    def __init__(self, config, *args, **kwargs):
        self.url = SERVICE.get(config.get('service'))
        self.sslVerify = config.get('verify_ssl')

    def make_rest_call(self, url, method):
        try:
            url = self.url
            response = requests.request(method, url, verify=self.sslVerify)
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response.content
            elif response.status_code == 404:
                return {'blocklist_ips': []}
            else:
                logger.error("{0}".format(errors.get(response.status_code, '')))
                raise ConnectorError("{0}".format(errors.get(response.status_code, response.text)))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def convert_datetime_to_epoch(date_time):
    d1 = time.strptime(date_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    epoch = datetime.datetime.fromtimestamp(time.mktime(d1)).strftime('%s')
    return epoch


def fetch_indicators(config, params, **kwargs):
    sf = BruteForceBlockerFeed(config)
    endpoint = ""
    ip_blocklist_list = []
    response = sf.make_rest_call(endpoint, 'GET')
    if response:
        ip_blocklist = str(response).split("\\n")
        last_modified_datetime = ip_blocklist[0].replace("\\t", " ").split(" ")[5].split(":")[1]
        for ip in ip_blocklist[5:-1]:
            ip_type = ip.replace("\\t", " ")
            ip = ip_type.split(" ")
            reported_date_time = ip[3] + 'T' + ip[4] + '.000Z'
            ip_blocklist_list.append(
                {'ip': ip[0], 'last_reported': int(convert_datetime_to_epoch(reported_date_time)),
                 'last_modified': int(last_modified_datetime), 'expires': int(last_modified_datetime) + 300,
                 'count': int(ip[6]),
                 'id': int(ip[7])})
        return ip_blocklist_list


def _check_health(config):
    try:
        sf = BruteForceBlockerFeed(config)
        return True
    except Exception as err:
        raise ConnectorError('Invalid URL or Credentials')


operations = {
    'fetch_indicators': fetch_indicators
}
