import logging, argparse, os, sys, json, logging, configparser, base64
import urllib.request, urllib.parse, urllib.error, urllib.response

# Super this because the logger returns non-standard digest header: X-Digest
class VSN300HTTPDigestAuthHandler(urllib.request.HTTPDigestAuthHandler):

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

class VSN700HTTPPreemptiveBasicAuthHandler(urllib.request.HTTPBasicAuthHandler):
    '''Preemptive basic auth: https://stackoverflow.com/a/24048772

    Instead of waiting for a 403 to then retry with the credentials,
    send the credentials if the url is handled by the password manager.
    Note: please use realm=None when calling add_password.'''
    def http_request(self, req):
        url = req.get_full_url()
        realm = None
        # this is very similar to the code from retry_http_basic_auth()
        # but returns a request object.
        user, pw = self.passwd.find_user_password(realm, url)
        if pw:
            raw = "%s:%s" % (user, pw)
            auth = 'Basic %s' % base64.b64encode(raw).strip()
            req.add_unredirected_header(self.auth_header, auth)
        return req

    https_request = http_request

class vsnx00Reader():

    def __init__(self, vsnmodel, host, user, password):

        self.vsnmodel = vsnmodel
        self.host = host
        self.user = user
        self.password = password
        self.realm = None
        # if self.vsnmodel == 'vsn300':
        #     self.realm = 'registered_user@power-one.com'
        # elif self.vsnmodel == 'vsn700':
        #     self.realm = None

        self.sys_data = dict()
        self.live_data = dict()
        self.vsnx00_data = dict()

        self.logger = logging.getLogger(__name__)

        self.url_host = "http://" + self.host

        self.passman = urllib.request.HTTPPasswordMgrWithPriorAuth()
        self.passman.add_password(self.realm, self.url_host, self.user, self.password)
        self.logger.debug("Check VSN model: {0}".format(self.vsnmodel))
        self.handler_vsn300 = VSN300HTTPDigestAuthHandler(self.passman)
        self.handler_vsn700 = VSN700HTTPPreemptiveBasicAuthHandler(self.passman)
        self.opener = urllib.request.build_opener(self.handler_vsn700, self.handler_vsn300)
        urllib.request.install_opener(self.opener)


    def get_vsn300_sys_data(self):

        # system data feed
        url_sys_data = self.url_host + "/v1/status"

        self.logger.info("Getting VSNX00 data from: {0}".format(url_sys_data))

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

        #self.logger.debug(self.sys_data)

        self.logger.debug("=======AX: start sys_data===========")
        self.logger.debug(parsed_json)
        self.logger.debug("=======AX: end sys_data===========")

        return self.sys_data
        # return parsed_json

    def get_vsn300_live_data(self):

        # Check if sys_data has been captured, Inv_ID is needed
        if not self.sys_data['device.invID']['Value']:
            self.logger.error("Inverter ID is empty")
            return

        # data feed
        url_live_data = self.url_host + "/v1/feeds"

        # select ser4 feed (energy data)
        device_path = "ser4:" + self.sys_data['device.invID']['Value']

        self.logger.info("Getting VSNX00 data from: {0}".format(url_live_data))

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

        # self.logger.debug(self.live_data)

        self.logger.debug("=======AX: start live_data===========")
        self.logger.debug(parsed_json)
        self.logger.debug("=======AX: end live_data===========")

        return self.live_data

    def get_vsn700_sys_data(self):

        # system data feed
        url_sys_data = self.url_host + "/v1/status"

        self.logger.info("Getting VSNX00 data from: {0}".format(url_sys_data))

        try:
            self.logger.info("Opening URL")
            json_response = urllib.request.urlopen(url_sys_data, timeout=10)
            self.logger.info("JSON to object")
            parsed_json = json.load(json_response)
        except Exception as e:
            self.logger.error(e)
            return

        self.logger.info("Get keys path data")
        path = parsed_json['keys']

        for k, v in path.items():

            self.logger.debug(str(k) + " - " + str(v['label']) + " - " + str(v['value']))

            self.sys_data[k] = {"Label": str(v['label']), "Value": v['value']}

        #self.logger.debug(self.sys_data)

        self.logger.debug("=======AX: start sys_data===========")
        self.logger.debug(parsed_json)
        self.logger.debug("=======AX: end sys_data===========")

        return self.sys_data
        # return parsed_json


def func_get_vsnx00_data(config):

    logger = logging.getLogger()

    pv_vsnmodel = config.get('VSNX00', 'vsnmodel').lower()
    pv_host = config.get('VSNX00', 'host').lower()
    pv_user = config.get('VSNX00', 'username').lower()
    pv_password = config.get('VSNX00', 'password')

    sys_data = dict()
    live_data = dict()
    vsnx00_data = dict()

    logger.info('Capturing live data from ABB VSNX00 logger')
    pv_meter = vsnx00Reader(pv_vsnmodel, pv_host, pv_user, pv_password)

    if pv_vsnmodel == 'vsn300':
        logger.debug("Start - get_vsn300_sys_data")
        return_data = pv_meter.get_vsn300_sys_data()

        if not return_data is None:
            sys_data = return_data
        else:
            sys_data = None
            logger.warning('No sys_data received from VSNX00 logger. Exiting.')
            return None

        logger.debug("End - get_vsn300_sys_data")

        logger.debug("Start - get_vsn300_live_data")
        live_data = dict()
        return_data = pv_meter.get_vsn300_live_data()

        if not return_data is None:
            live_data = return_data
        else:
            live_data = None
            logger.warning('No live_data received from VSNX00 logger. Exiting.')
        logger.debug("End - get_vsn300_live_data")

        logger.debug("=======sys_data===========")
        logger.debug(sys_data)
        logger.debug("=======live_data===========")
        logger.debug(live_data)

        # Merge the two dicts
        sys_data.update(live_data)

    elif pv_vsnmodel == 'vsn700':
        logger.debug("Start - get_vsn700_sys_data")
        return_data = pv_meter.get_vsn700_sys_data()

        if not return_data is None:
            sys_data = return_data
        else:
            sys_data = None
            logger.warning('No sys_data received from VSNX00 logger. Exiting.')
        logger.debug("End - get_vsn700_sys_data")

        logger.debug("=======sys_data===========")
        logger.debug(sys_data)

    # JSONify the merged dict
    vsnx00_data = json.dumps(sys_data)

    logger.debug("=======vsnx00_data===========")
    logger.debug(vsnx00_data)

    return vsnx00_data


def write_config(path):

    config = configparser.ConfigParser(allow_no_value=True)

    config.add_section('VSNX00')
    config.set('VSNX00', '# vsnmodel: VSN300 or VSN700')
    config.set('VSNX00', '# hostname: hostname/IP of the VSN datalogger')
    config.set('VSNX00', '# username: guest or admin')
    config.set('VSNX00', '# password: if user is admin, set the password')
    config.set('VSNX00', '# ')
    config.set('VSNX00', 'vsnmodel', 'VSN300')
    config.set('VSNX00', 'host', '192.168.1.112')
    config.set('VSNX00', 'username', 'guest')
    config.set('VSNX00', 'password', 'pw')

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
    default_cfg = "vsnx00-monitor.cfg"

    parser = argparse.ArgumentParser(description="VSNX00 Monitor help")
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

    logger.info("STARTING VSNX00 data capture")
    vsnx00_data = func_get_vsnx00_data(config)

    if vsnx00_data is None:
        logger.error("Error capturing data. Exiting...")
    else:
        logger.info("Data capture ended. Here's the JSON data:")
        logger.info("========= VSNX00 Data =========")
        logger.info(vsnx00_data)
        logger.info("========= VSNX00 Data =========")
        return vsnx00_data

# Begin
try:
    print(main())
except KeyboardInterrupt:
    # quit
    print ("...Ctrl-C received!... exiting")
    sys.exit()