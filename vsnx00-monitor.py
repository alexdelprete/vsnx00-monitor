import argparse
import base64
import configparser
import json
import logging
import os
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import (
    HTTPBasicAuthHandler,
    HTTPDigestAuthHandler,
    HTTPPasswordMgrWithPriorAuth,
    build_opener,
    install_opener,
    parse_http_list,
    parse_keqv_list,
    urlopen,
)


def make_request(requested_url):
    try:
        # DO NOT pass context parameter - it bypasses the installed opener with auth handlers!
        return urlopen(requested_url, timeout=10)
    except HTTPError as error:
        print(error.status, error.reason)
    except URLError as error:
        print(error.reason)
    except TimeoutError:
        print("Request timed out")


# Super this because the logger returns non-standard digest header: X-Digest
class VSN300HTTPDigestAuthHandler(HTTPDigestAuthHandler):
    def retry_http_digest_auth(self, req, auth):
        token, challenge = auth.split(" ", 1)
        chal = parse_keqv_list(parse_http_list(challenge))
        auth = self.get_authorization(req, chal)
        if auth:
            auth_val = "X-Digest %s" % auth
            if req.headers.get(self.auth_header, None) == auth_val:
                return None
            req.add_unredirected_header(self.auth_header, auth_val)
            resp = urlopen(req, timeout=req.timeout)
            return resp

    def http_error_auth_reqed(self, auth_header, host, req, headers):
        authreq = headers.get(auth_header, None)
        if self.retried > 5:
            # Don't fail endlessly - if we failed once, we'll probably
            # fail a second time. Hm. Unless the Password Manager is
            # prompting for the information. Crap. This isn't great
            # but it's better than the current 'repeat until recursion
            # depth exceeded' approach <wink>
            raise HTTPError(
                req.get_full_url(), 401, "digest auth failed", headers, None
            )
        else:
            self.retried += 1
        if authreq:
            scheme = authreq.split()[0]
            if scheme.lower() == "x-digest":
                return self.retry_http_digest_auth(req, authreq)


class VSN700HTTPPreemptiveBasicAuthHandler(HTTPBasicAuthHandler):
    # Preemptive basic auth: https://stackoverflow.com/a/24048772
    # Instead of waiting for a 403 to then retry with the credentials,
    # send the credentials if the url is handled by the password manager.
    # Note: please use realm=None when calling add_password
    def http_request(self, req):
        url = req.get_full_url()
        realm = None
        # this is very similar to the code from retry_http_basic_auth()
        # but returns a request object
        user, pw = self.passwd.find_user_password(realm, url)  # type: ignore
        if pw:
            raw = "%s:%s" % (user, pw)
            raw_b64 = base64.standard_b64encode(raw.encode("utf-8"))
            auth_val = "Basic %s" % raw_b64.decode("utf-8").strip()
            req.add_unredirected_header(self.auth_header, auth_val)
        return req

    https_request = http_request


class vsnx00Reader:
    def _detect_device_type(self):
        """
        Detect whether device is VSN300 or VSN700 by analyzing authentication challenge.

        Makes an unauthenticated request to /v1/status and examines the WWW-Authenticate
        header in the 401 response to determine the authentication scheme required.

        Returns:
            str: 'VSN300' if X-Digest/Digest auth is required, 'VSN700' if Basic auth

        Raises:
            Exception: If device type cannot be detected after retries
        """
        probe_url = self.url + "/v1/status"
        max_retries = 3
        retry_delay = 2  # seconds

        for attempt in range(max_retries):
            try:
                self.logger.info(
                    f"Detecting device type (attempt {attempt + 1}/{max_retries})..."
                )
                # Make request without authentication - expect 401
                urlopen(probe_url, timeout=10)
                # If we get here (no 401), something unexpected happened
                self.logger.warning("Device did not require authentication - unexpected")

            except HTTPError as error:
                if error.status == 401:
                    # Expected - examine the WWW-Authenticate header
                    auth_header = error.headers.get("WWW-Authenticate", "")
                    self.logger.debug(f"WWW-Authenticate header: {auth_header}")

                    if "x-digest" in auth_header.lower() or "digest" in auth_header.lower():
                        self.logger.info("Detected VSN300 device (X-Digest authentication)")
                        return "VSN300"
                    elif "basic" in auth_header.lower():
                        self.logger.info("Detected VSN700 device (Basic authentication)")
                        return "VSN700"
                    else:
                        self.logger.warning(
                            f"Unknown authentication scheme: {auth_header}"
                        )
                else:
                    # Unexpected HTTP error
                    self.logger.warning(
                        f"Unexpected HTTP error {error.status}: {error.reason}"
                    )

            except URLError as error:
                # Network error - retry
                self.logger.warning(
                    f"Network error during detection: {error.reason}"
                )
                if attempt < max_retries - 1:
                    self.logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)

            except TimeoutError:
                self.logger.warning("Request timed out during device detection")
                if attempt < max_retries - 1:
                    self.logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)

        # If we get here, all retries failed
        raise Exception(
            f"Failed to detect device type after {max_retries} attempts. "
            "Please check device connectivity and try again."
        )

    def __init__(self, url, user, password):
        self.logger = logging.getLogger(__name__)

        self.url = url
        parsed_url = urlparse(url)
        self.host = parsed_url.hostname
        self.user = user
        self.password = password
        self.realm = None

        self.status_data = dict()
        self.live_data = dict()
        self.feeds_data = dict()

        # Detect device type first
        device_type = self._detect_device_type()

        # Setup authentication based on detected device type
        self.passman = HTTPPasswordMgrWithPriorAuth()
        self.passman.add_password(self.realm, self.url, self.user, self.password)

        if device_type == "VSN300":
            self.logger.info("Initializing VSN300 X-Digest authentication handler")
            handler = VSN300HTTPDigestAuthHandler(self.passman)
        else:  # VSN700
            self.logger.info("Initializing VSN700 Basic authentication handler")
            handler = VSN700HTTPPreemptiveBasicAuthHandler(self.passman)

        self.opener = build_opener(handler)
        install_opener(self.opener)

    def get_vsnx00_status_data(self):
        # system data feed
        url_status_data = self.url + "/v1/status"

        self.logger.info("Getting VSNX00 status data from: {0}".format(url_status_data))

        self.logger.info("Opening status URL")
        json_response = make_request(url_status_data)
        if json_response is None:
            return None
        self.logger.info("JSON to object")
        parsed_json = json.load(json_response)

        self.logger.debug("======= get_vsnx00_status_data(): parsed_json ===========")
        self.logger.debug(parsed_json)
        self.logger.debug("======= get_vsnx00_status_data(): END ===========")

        return parsed_json

    def get_vsnx00_live_data(self):
        # system data feed
        url_live_data = self.url + "/v1/livedata"

        self.logger.info("Getting VSNX00 livedata from: {0}".format(url_live_data))

        self.logger.info("Opening livedata URL")
        json_response = make_request(url_live_data)
        if json_response is None:
            return None
        self.logger.info("JSON to object")
        parsed_json = json.load(json_response)

        self.logger.debug("======= get_vsnx00_live_data(): parsed_json ===========")
        self.logger.debug(parsed_json)
        self.logger.debug("======= get_vsnx00_live_data(): END ===========")

        return parsed_json

    def get_vsnx00_feeds_data(self):
        # system data feed
        url_feeds_data = self.url + "/v1/feeds"

        self.logger.info("Getting VSNX00 feeds data from: {0}".format(url_feeds_data))

        self.logger.info("Opening feeds URL")
        json_response = make_request(url_feeds_data)
        if json_response is None:
            return None
        self.logger.info("JSON to object")
        parsed_json = json.load(json_response)

        self.logger.debug("======= get_vsnx00_feeds_data(): parsed_json ===========")
        self.logger.debug(parsed_json)
        self.logger.debug("======= get_vsnx00_feeds_data(): END ===========")

        return parsed_json


def get_vsnx00_data(config):
    logger = logging.getLogger()

    pv_url = config.get("VSNX00", "url").lower()
    pv_user = config.get("VSNX00", "username")
    pv_password = config.get("VSNX00", "password")

    status_data = dict()
    live_data = dict()
    feeds_data = dict()
    vsnx00_data = dict()

    logger.info("Capturing live data from ABB VSNX00 logger")
    pv_meter = vsnx00Reader(pv_url, pv_user, pv_password)

    # VSNx00 status
    logger.debug("Start - get_vsnx00_status_data")
    status_data = pv_meter.get_vsnx00_status_data()
    if status_data is None:
        logger.warning("No status_data received from VSNX00 logger. Exiting.")
        return None
    else:
        # Append dict
        vsnx00_data.update(status_data)
    logger.debug("End - get_vsnx00_status_data")

    # VSNx00 livedata
    logger.debug("Start - get_vsnx00_live_data")
    live_data = pv_meter.get_vsnx00_live_data()
    if live_data is None:
        logger.warning("No live_data received from VSNX00 logger. Exiting.")
        return None
    else:
        # Append dict
        vsnx00_data.update(live_data)
    logger.debug("End - get_vsnx00_live_data")

    # VSNx00 feeds
    logger.debug("Start - get_vsnx00_feeds_data")
    feeds_data = pv_meter.get_vsnx00_feeds_data()
    if feeds_data is None:
        logger.warning("No feeds_data received from VSNX00 logger. Exiting.")
        return None
    else:
        # Append dict
        vsnx00_data.update(feeds_data)
    logger.debug("End - get_vsnx00_feeds_data")

    logger.debug("======= get_vsnx00_data(): vsnx00_data ===========")
    logger.debug(vsnx00_data)
    logger.debug("======= get_vsnx00_data(): END ===========")

    # Write separate JSON files for each endpoint
    logger.info("Writing status data to vsnx00_data_status.json")
    with open("vsnx00_data_status.json", "w") as f:
        json.dump(status_data, f, indent=2)

    logger.info("Writing livedata to vsnx00_data_livedata.json")
    with open("vsnx00_data_livedata.json", "w") as f:
        json.dump(live_data, f, indent=2)

    logger.info("Writing feeds data to vsnx00_data_feeds.json")
    with open("vsnx00_data_feeds.json", "w") as f:
        json.dump(feeds_data, f, indent=2)

    # JSONify and prettify the three merged dicts
    vsnx00_data = json.dumps(vsnx00_data, indent=2)

    # return json response
    return vsnx00_data


def write_config(path):
    config = configparser.ConfigParser(allow_no_value=True)

    config.add_section("VSNX00")
    config.set(
        "VSNX00", "# url: URL of the VSN datalogger (including HTTP/HTTPS prefix)"
    )
    config.set("VSNX00", "# username: guest or admin")
    config.set("VSNX00", "# password: if user is admin, set the password")
    config.set("VSNX00", "# ")
    config.set("VSNX00", "url", "192.168.1.112")
    config.set("VSNX00", "username", "guest")
    config.set("VSNX00", "password", "pw")

    path = os.path.expanduser(path)

    with open(path, "w") as configfile:
        config.write(configfile)

        print(("Config has been written to: {0}").format(os.path.expanduser(path)))


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
    parser.add_argument(
        "-c",
        "--config",
        nargs="?",
        const=default_cfg,
        help="config file location",
        metavar="path/file",
    )
    parser.add_argument(
        "-w",
        "--writeconfig",
        nargs="?",
        const=default_cfg,
        help="create a default config file",
        metavar="path/file",
    )
    parser.add_argument(
        "-v", "--verbose", help="verbose logging", action="store_true", default=False
    )
    parser.add_argument(
        "-d", "--debug", help="debug logging", action="store_true", default=False
    )

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
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

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
    vsnx00_data = get_vsnx00_data(config)

    if vsnx00_data is None:
        logger.error("Error capturing data. Exiting...")
    else:
        logger.info("Data capture complete. Here's the JSON data:")
        logger.info("========= VSNX00 Data =========")
        logger.info(vsnx00_data)
        logger.info("========= VSNX00 Data =========")
        print("\nData capture complete. Created 3 files:")
        print("  - vsnx00_data_status.json")
        print("  - vsnx00_data_livedata.json")
        print("  - vsnx00_data_feeds.json\n")
        return vsnx00_data


# Begin
try:
    # print(main())
    main()
except KeyboardInterrupt:
    # quit
    print("...Ctrl-C received!... exiting")
    sys.exit()
