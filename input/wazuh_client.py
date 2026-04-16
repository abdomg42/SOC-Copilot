import requests, os
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()

WAZUH_HOST = os.getenv('WAZUH_HOST', '')
WAZUH_PORT = os.getenv('WAZUH_PORT', '')
WAZUH_USERNAME = os.getenv('WAZUH_USERNAME', '')
WAZUH_PASSWORD = os.getenv('WAZUH_PASSWORD', '')
BASE_URL = f'https://{WAZUH_HOST}:{WAZUH_PORT}/api'


def get_token():
    r = requests.post(f'{BASE_URL}/security/user/authenticate',
                      auth=(WAZUH_USERNAME, WAZUH_PASSWORD),
                        verify=False,
                        timeout=10)
    r.raise_for_status()
    return r.json()['data']['token']

