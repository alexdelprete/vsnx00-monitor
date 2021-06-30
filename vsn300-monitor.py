import logging, argparse, os, sys, json, logging, configparser
import urllib.request, urllib.error, urllib.parse

# Super this because the logger returns non-standard digest header: X-Digest
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

    def __init__(self, host, user, password):
        
        self.host = host
        self.user = user
        self.password = password
        self.realm = 'registered_user@power-one.com'

        self.logger = logging.getLogger(__name__)

        self.url_host = "http://" + self.host

        self.passman = urllib.request.HTTPPasswordMgr()
        self.passman.add_password(self.realm, self.url_host, self.user, self.password)
        self.handler = MyHTTPDigestAuthHandler(self.passman)
        self.opener = urllib.request.build_opener(self.handler)
        urllib.request.install_opener(self.opener)
        self.sys_data = dict()
        self.live_data = dict()


    def get_sys_data(self):

        # system data feed
        url_sys_data = self.url_host + "/v1/status"

        self.logger.info("Getting VSN300 data from: {0}".format(url_sys_data))

        try:
            json_response = urllib.request.urlopen(url_sys_data, timeout=10)
            parsed_json = json.load(json_response)
        except Exception as e:
            self.logger.error(e)
            return

        path = parsed_json['keys']
        
        for k, v in path.items():

            self.logger.debug(str(k) + " - " + str(v['label']) + " - " + str(v['value']))

            self.sys_data[k] = {"Label": str(v['label']), "Value": v['value']}

        self.logger.debug(self.sys_data)

        return self.sys_data

    def get_live_data(self):

        # Check if sys_data has been captured, Inv_ID is needed
        if not self.sys_data['device.invID']['Value']:
            self.logger.error("Inverter ID is empty")
            return
            
        # data feed
        url_live_data = self.url_host + "/v1/feeds/"

        # select ser4 feed (energy data)
        device_path = "ser4:" + self.sys_data['device.invID']['Value']

        self.logger.info("Getting VSN300 data from: {0}".format(url_live_data))

        try:
            json_response = urllib.request.urlopen(url_live_data, timeout=10)
            parsed_json = json.load(json_response)
        except Exception as e:
            self.logger.error(e)
            return

        path = parsed_json['feeds'][device_path]['datastreams']
        
        for k, v in path.items():

            # ADP: get only latest record (0)
            idx = 0

            self.logger.debug(str(k) + " - " + str(v['title']) + " - " + str(v['data'][idx]['value']) + " - " + str(v['units']))

            self.live_data[k] = {"Title": str(v['title']), "Value": v['data'][idx]['value'], "Unit": str(v['units'])}

        self.logger.debug(self.live_data)

        return self.live_data


def func_get_vsn300_data(config):

    logger = logging.getLogger()

    pv_host = config.get('VSN300', 'host')
    pv_user = config.get('VSN300', 'username')
    pv_password = config.get('VSN300', 'password')

    sys_data = dict()
    live_data = dict()
    vsn300_data = dict()

    logger.info('Capturing live data from ABB VSN300 logger')
    pv_meter = Vsn300Reader(pv_host, pv_user, pv_password)

    logger.debug("Start - get_sys_data")
    return_data = pv_meter.get_sys_data()
    if not return_data is None:
        sys_data = return_data
    else:
        sys_data = None
        logger.warning('No sys_data received from VSN300 logger. Exiting.')
        return None
    logger.debug("End - get_sys_data")

    logger.debug("Start - get_live_data")
    return_data = pv_meter.get_live_data()
    if not return_data is None:
        live_data = return_data
    else:
        live_data = None
        logger.warning('No live_data received from VSN300 logger. Exiting.')
    logger.debug("End - get_live_data")

    logger.debug("=======sys_data===========")
    logger.debug(sys_data)
    logger.debug("=======live_data===========")
    logger.debug(live_data)

    # Merge the two dicts
    sys_data.update(live_data)

    # JSONify the merged dict
    vsn300_data = json.dumps(sys_data)

    logger.debug("=======vsn300_data===========")
    logger.debug(vsn300_data)
    
    return vsn300_data


def write_config(path):

    config = configparser.ConfigParser(allow_no_value=True)

    config.add_section('VSN300')
    config.set('VSN300', '# hostname: hostname or IP of the logger')
    config.set('VSN300', '# username: is either guest or admin')
    config.set('VSN300', '# password: as set on webui')
    config.set('VSN300', '# ')
    config.set('VSN300', 'host', '192.168.1.12')
    config.set('VSN300', 'username', 'guest')
    config.set('VSN300', 'password', 'pw')

    path = os.path.expanduser(path)

    with open(path, 'wb') \
            as configfile:
        config.write(configfile)

        print(("Config has been written to: {0}").\
            format(os.path.expanduser(path)))


def read_config(path):

    if not os.path.isfile(path):
        print(("Config file not found: {0}".format(path)))
        exit()

    else:

        config = configparser.RawConfigParser()
        config.read(path)

        return config


def main():

    # Init
    default_cfg = "vsn300-monitor.cfg"

    parser = argparse.ArgumentParser(description="VSN300 Monitor help")
    parser.add_argument('-c', '--config', nargs='?', const=default_cfg, help="config file location", metavar="path/file")
    parser.add_argument('-w', '--writeconfig', nargs='?',const=default_cfg, help="create a default config file", metavar="path/file")
    parser.add_argument('-v', '--verbose', help='verbose logging', action="store_true", default=False)
    parser.add_argument('-d', '--debug', help='debug logging', action="store_true", default=False)

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

    if args.writeconfig:
        write_config(args.create_config)
        exit()

    if args.config is None:
        path = default_cfg
    else:
        path = args.config

    path = os.path.expanduser(path)

    config = read_config(path)

    logger.info("STARTING VSN300 data capture")
    vsn300_data = func_get_vsn300_data(config)

    if vsn300_data is None:
        logger.error("Error capturing data. Exiting...")
    else:
        logger.info("Data capture ended. Here's the JSON data:")
        logger.info("========= VSN300 Data =========")
        logger.info(vsn300_data)
        logger.info("========= VSN300 Data =========")
        return vsn300_data

# Begin
try:
    print(main())
except KeyboardInterrupt:
    # quit
    print ("...Ctrl-C received!... exiting")
    sys.exit()