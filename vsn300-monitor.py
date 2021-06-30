import urllib.request, urllib.error, urllib.parse
import logging
import argparse
import os
import sys
import json
import logging


# Super this because the logger returns non-standard digest header: x-Digest
class MyHTTPDigestAuthHandler(urllib.request.HTTPDigestAuthHandler):

    def retry_http_digest_auth(self, req, auth):
        token, challenge = auth.split(' ', 1)
        chal = urllib.request.parse_keqv_list(urllib.request.parse_http_list(challenge))
        auth = self.get_authorization(req, chal)
        if auth:
            auth_val = 'X-Digest %s' % auth
            if req.headers.get(self.auth_header, None) == auth_val:
                return None
            req.add_unredirected_header(self.auth_header, auth_val)
            resp = self.parent.open(req, timeout=req.timeout)
            return resp

    def http_error_auth_reqed(self, auth_header, host, req, headers):
        authreq = headers.get(auth_header, None)
        if self.retried > 5:
            # Don't fail endlessly - if we failed once, we'll probably
            # fail a second time. Hm. Unless the Password Manager is
            # prompting for the information. Crap. This isn't great
            # but it's better than the current 'repeat until recursion
            # depth exceeded' approach <wink>
            raise urllib.error.HTTPError(req.get_full_url(), 401, "digest auth failed", headers, None)
        else:
            self.retried += 1
        if authreq:
            scheme = authreq.split()[0]
            if scheme.lower() == 'x-digest':
                return self.retry_http_digest_auth(req, authreq)


class Vsn300Reader():

    def __init__(self, host, user, password, inverter_id):
        
        self.host = host
        self.user = user
        self.password = password
        self.realm = 'registered_user@power-one.com'
        self.inverter_id = inverter_id

        self.logger = logging.getLogger(__name__)

        self.url_host = "http://" + self.host

        self.passman = urllib.request.HTTPPasswordMgr()
        self.passman.add_password(self.realm, self.url_host, self.user, self.password)
        self.handler = MyHTTPDigestAuthHandler(self.passman)
        self.opener = urllib.request.build_opener(self.handler)
        urllib.request.install_opener(self.opener)

    def get_sys_data(self):

        # system data feed
        url_sys_data = "http://" + self.host + "/v1/status"
        sys_data = dict()

        self.logger.info("Getting VSN300 data from: {0}".format(url_sys_data))

        try:
            json_response = urllib.request.urlopen(url_sys_data, timeout=10)
            parsed_json = json.load(json_response)
        except Exception as e:
            self.logger.error(e)
            return

        path = parsed_json['keys']
        
        self.logger.debug(path)

        for k, v in path.items():

            self.logger.debug(str(k) + " - " + str(v['label']) + " - " + str(v['value']))

            sys_data[k] = {"Label": str(v['label']), "Value": v['value']}

        self.logger.info(sys_data)

        return sys_data

    def get_live_data(self):

        # data feed
        url_live_data = "http://" + self.host + "/v1/feeds/"

        # select ser4 feed (energy data)
        device_path = "ser4:" + self.inverter_id
        live_data = dict()

        self.logger.info("Getting VSN300 data from: {0}".format(url_live_data))

        try:
            json_response = urllib.request.urlopen(url_live_data, timeout=10)
            parsed_json = json.load(json_response)
        except Exception as e:
            self.logger.error(e)
            return

        path = parsed_json['feeds'][device_path]['datastreams']
        
        self.logger.debug(path)

        for k, v in path.items():

            # ADP: get only latest record (0)
            idx = 0

            self.logger.debug(str(k) + " - " + str(v['title']) + " - " + " - " + str(v['data'][idx]['value']))

            live_data[k] = {"Title": str(v['title']), "Value": v['data'][idx]['value'], "Unit": str(v['units'])}

        self.logger.info(live_data)

        return live_data


default_cfg = ".\vsn300-monitor.cfg"

parser = argparse.ArgumentParser(description="Energy Monitor help")
parser.add_argument('-c', '--config', nargs='?', const=default_cfg,
                    help='Config file location')
parser.add_argument('--create-config', nargs='?',
                    const=default_cfg,
                    help="Create a config file, defaults to "
                         "energy-monitor.cfg or specify an "
                         "alternative location",
                    metavar="path")
parser.add_argument('-v', '--verbose', help='Verbose logging ',
                    action="store_true", default=False)
parser.add_argument('--debug', help='Debug logging ',
                    action="store_true", default=False)

args = parser.parse_args()

# Set logging
logger = logging.getLogger()

if args.verbose:
    logger.setLevel(logging.INFO)
elif args.debug:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.WARNING)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - '
                              '%(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)

def func_get_vsn300_data(config):

    pv_host = config.get('VSN300', 'host')
    pv_interval = config.getint('VSN300', 'interval')
    pv_inverter_serial = config.get('VSN300', 'inverter_serial')
    pv_user = config.get('VSN300', 'username')
    pv_password = config.get('VSN300', 'password')

    global glob_sys_data
    global glob_live_data

    logger.info('GETTING live data from ABB VSN300 logger')
    pv_meter = Vsn300Reader(pv_host, pv_user, pv_password, pv_inverter_serial)

    logger.debug("Start - get_sys_data")
    return_data = pv_meter.get_sys_data()
    if not return_data is None:
        glob_sys_data = return_data
    else:
        glob_sys_data = None
        logger.warning('No data received from VSN300 logger')
    logger.debug("End - get_sys_data")

    logger.debug("Start - get_live_data")
    return_data = pv_meter.get_live_data()
    if not return_data is None:
        glob_live_data = return_data
    else:
        glob_live_data = None
        logger.warning('No data received from VSN300 logger')
    logger.debug("End - get_live_data")


def write_config(path):

    import configparser

    config = configparser.ConfigParser(allow_no_value=True)

    config.add_section('VSN300')
    config.set('VSN300', '# enable: turn data retrieval on or off')
    config.set('VSN300', '# hostname:  or IP of the logger')
    config.set('VSN300', '# inverter_serial: serial can be found in the'
                         ' webui: data -> '  'system info ->'
                         ' inverter info -> serial ')
    config.set('VSN300', '# interval: interval to read data from logger, '
                         'logger does only refresh data every 60 seconds, '
                         'polling more often is useless ')
    config.set('VSN300', '# username: is either guest or admin')
    config.set('VSN300', '# password: as set on webui')
    config.set('VSN300', '# ')

    config.set('VSN300', 'enable', 'true')
    config.set('VSN300', 'host', '192.168.1.12')
    config.set('VSN300', 'inverter_serial', 'XXXXXX-XXXX-XXXX')
    config.set('VSN300', 'interval', '60')
    config.set('VSN300', 'username', 'guest')
    config.set('VSN300', 'password', 'password')

    path = os.path.expanduser(path)

    with open(path, 'wb') \
            as configfile:
        config.write(configfile)

        print(("Config has been written to: {0}").\
            format(os.path.expanduser(path)))


def read_config(path):

    import configparser

    if not os.path.isfile(path):
        print(("Config file not found: {0}".format(path)))
        exit()

    else:

        config = configparser.RawConfigParser()
        config.read(path)

        return config


def main():

    if args.create_config:
        write_config(args.create_config)
        exit()

    if args.config is None:
        path = default_cfg
    else:
        path = args.config

    path = os.path.expanduser(path)

    config = read_config(path)
    pv_enable = config.getboolean('VSN300', 'enable')
    pv_interval = config.getint('VSN300', 'interval')

    if pv_enable:
        logger.info("STARTING PV/VSN300 data retrieve")
        func_get_vsn300_data(config)

try:
    main()
except KeyboardInterrupt:
    # quit
    print ("...Ctrl-C received!... exiting")
    sys.exit()