"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

import requests, time, json
import os.path
import uuid

from datetime import datetime

from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.files import get_ingestion_base_dir

logger = get_logger('brute-force-blocker-feed')

errors = {
    400: 'Bad/Invalid Request',
    401: 'Unauthorized: Invalid credentials provided failed to authorize',
    403: 'Access Denied',
    404: 'Not Found',
    500: 'Internal Server Error'
}


class BruteForceBlockerFeed(object):
    def __init__(self, config, *args, **kwargs):
        self.url = config.get('service')
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
    epoch = datetime.fromtimestamp(time.mktime(d1)).strftime('%s')
    return epoch


def find_indicators(ip_blocklist, last_modified_datetime):
    ip_blocklist_list = []
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


def fetch_indicators(config, params, **kwargs):
    sf = BruteForceBlockerFeed(config)
    endpoint = ""
    last_pull_time = params.get('last_pull_time')
    response = sf.make_rest_call(endpoint, 'GET')
    if response:
        ip_blocklist = str(response).split("\\n")
        last_modified_datetime = ip_blocklist[0].replace("\\t", " ").split(" ")[5].split(":")[1]
        if last_pull_time:
            last_pull_time = int(convert_datetime_to_epoch(last_pull_time))
            if int(last_modified_datetime) > last_pull_time:
                ips_list = find_indicators(ip_blocklist, last_modified_datetime)
                return ips_list
            else:
                return []
        else:
            ips_list = find_indicators(ip_blocklist, last_modified_datetime)
            return ips_list


def download_indicators(config, params, **kwargs):
    sf = BruteForceBlockerFeed(config)
    config_id = config.get('config_id')
    endpoint = ""
    last_pull_time = params.get('last_pull_time')
    response = sf.make_rest_call(endpoint, 'GET')
    if response:
        ip_blocklist = str(response).split("\\n")
        last_modified_datetime = ip_blocklist[0].replace("\\t", " ").split(" ")[5].split(":")[1]
        if last_pull_time:
            last_pull_time = int(convert_datetime_to_epoch(last_pull_time))
            if int(last_modified_datetime) > last_pull_time:
                ips_list = find_indicators(ip_blocklist, last_modified_datetime)
            else:
                ips_list = []
        else:
            ips_list = find_indicators(ip_blocklist, last_modified_datetime)
        base_indicator_dir = get_ingestion_base_dir(**kwargs)
        try:
            os.makedirs(base_indicator_dir, exist_ok=True)
        except Exception as e:
            base_indicator_dir = '/tmp/'
            logger.warn("Not able to create dir for downloading indicators")

        config_dir = base_indicator_dir + config_id + '/'
        try:
            os.makedirs(config_dir, exist_ok=True)
        except Exception as e:
            pass
        file_name = str(uuid.uuid4()) + '.json'
        file_path = os.path.join(config_dir, file_name)
        with open(file_path, "w") as json_file:
            json.dump(ips_list, json_file, indent=2)

        return {"files": [file_path.replace(base_indicator_dir, '')], "last_pull_datetime": datetime.now()}


def _check_health(config):
    sf = BruteForceBlockerFeed(config)
    return True


operations = {
    'fetch_indicators': fetch_indicators,
    'download_indicators': download_indicators
}
