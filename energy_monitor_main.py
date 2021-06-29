import logging
import threading
import abb_vsn300
import pvoutput
import argparse
import os
import datetime
import time
import sys

default_cfg = ".\energy-monitor.cfg"

parser = argparse.ArgumentParser(description="Energy Monitor help")
parser.add_argument('-c', '--config', nargs='?', const=default_cfg,
                    help='Config file location')
parser.add_argument('-d', '--daemon', help='Run as Daemon ',
                    action="store_true", default=False)
parser.add_argument('-s', '--simulate', help='Run in simulate mode',
                    action="store_true", default=False)
parser.add_argument('--create-config', nargs='?',
                    const=default_cfg,
                    help="Create a config file, defaults to "
                         "~/energy-monitor.cfg or specify an "
                         "alternative location",
                    metavar="path")
parser.add_argument('-v', '--verbose', help='Verbose logging ',
                    action="store_true", default=False)
parser.add_argument('--debug', help='Debug logging ',
                    action="store_true", default=False)
# parser.add_argument('-l', '--logfile', help='Send output to logfile  ',
#                     action="store_true", default=False)

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

lock = threading.RLock()

def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def time_in_range(start, end, x):
    """Return true if x is in the range [start, end]"""
    if start <= end:
        return start <= x <= end
    else:
        return start <= x or x <= end


def thread_get_pv_data(config, daemon=False, simulate=False):

    pv_host = config.get('VSN300', 'host')
    pv_interval = config.getint('VSN300', 'interval')
    pv_inverter_serial = config.get('VSN300', 'inverter_serial')
    pv_user = config.get('VSN300', 'username')
    pv_password = config.get('VSN300', 'password')

    global glob_pv_data

    logger.debug("Acquire Lock - get_pv_data")
    lock.acquire()

    logger.info('GETTING data from ABB VSN300 logger')
    pv_meter = abb_vsn300.Vsn300Reader(pv_host, pv_user, pv_password,
                                       pv_inverter_serial, simulate)

    return_data = pv_meter.get_last_stats()

    if not return_data is None:
        glob_pv_data = return_data
        #send_data_to_carbon(config, return_data, "pv.")

    else:
        glob_pv_data = None
        logger.warning('No data received from VSN300 logger')

    logger.debug("Release Lock - get_pv_data")
    lock.release()

    if daemon:
        t = threading.Timer(pv_interval, thread_get_pv_data,
                            [config, daemon, simulate])
        t.daemon = daemon
        t.start()



def thread_send_data_to_pvoutput(config, daemon=False):

    api_key = config.get('PVOUTPUT', 'api_key')
    system_id = config.get('PVOUTPUT', 'system_id')
    interval = config.getint('PVOUTPUT', 'interval')

    now = datetime.datetime.now()
    date_now = now.strftime('%Y%m%d')
    time_now = now.strftime('%H:%M')
    total_wh_generated = None
    watt_generated = None
    kwh_out_high = None
    kwh_out_low = None
    kwh_high = None
    kwh_low = None
    watt_export = None
    watt_import = None
    temp_c = None
    vdc = None
    gas_m3 = None
    inverter_temp = None

    logger.info('SENDING metrics to pvoutput.org')
    pv_connection = pvoutput.Connection(api_key, system_id)

    logger.debug("Acquire Lock - send pvoutput")
    lock.acquire()

    if 'glob_pv_data' in globals():
        if glob_pv_data is not None:

            if 'm101_1_W' in glob_pv_data:
                watt_generated = float(glob_pv_data['m101_1_W']) * 1000
                logger.info('Watt generated: {0}'.format(watt_generated))

            if 'm64061_1_DayWH' in glob_pv_data:
                day_wh_generated = float(glob_pv_data['m64061_1_DayWH']) * 1000
                logger.info('Day wH generated: {0}'.format(day_wh_generated))

            if 'm64061_1_TotalWH' in glob_pv_data:
                total_wh_generated = float(glob_pv_data[
                    'm64061_1_TotalWH']) * 1000
                logger.info('Total (Lifetime) wH generated: {0}'
                            .format(total_wh_generated))

            if 'm101_1_DCV' in glob_pv_data:
                vdc = glob_pv_data['m101_1_DCV']
                logger.info('Volt DC: {0}'.format(vdc))

            if 'm101_1_TmpCab' in glob_pv_data:
                inverter_temp = glob_pv_data['m101_1_TmpCab']
                logger.info('Inverter Temperature: {0}'.format(inverter_temp))

        else:

            logger.warning('No PV Data! Sun down? or Logger Down?')

    # Sending generation data (gross), separate from import/export (net).
    # See also: http://pvoutput.org/help.html#api-addstatus (net data)
    # we need to send gross before net so they will be merged correctly


            # params['v1'] = energy_exp = energy generation
            # params['v2'] = power_exp = power generation
            # params['v3'] = energy_imp = energy consumption
            # params['v4'] = power_imp = power consumption

    logger.info("Sending (gross) pv generation data to pvoutput")
    pv_connection.add_status(date=date_now,
                             time=time_now,
                             energy_exp=total_wh_generated,
                             power_exp=watt_generated,
                             energy_imp=None,
                             power_imp=None,
                             temp=temp_c,
                             vdc=vdc,
                             cumulative=True,
                             net=False,
                             v8=gas_m3,
                             v7=inverter_temp,
                             v9=kwh_out_high,
                             v10=kwh_out_low,
                             v11=kwh_high,
                             v12=kwh_low)

    logger.info("Sending (net) import/export data to pvoutput")
    pv_connection.add_status(date=date_now,
                             time=time_now,
                             energy_exp=None,
                             power_exp=watt_export,
                             energy_imp=None,
                             power_imp=watt_import,
                             temp=None,
                             vdc=None,
                             cumulative=False,
                             net=True)

    # eod_start = datetime.time(10,55,0)
    # eod_stop =  datetime.time(12,10,0)
    # eod_now = datetime.datetime.now().time()
    # eod_cm = "EOD generated at: {0} {1}".format(date_now, time_now)
    # eod_run = 0
    #
    # print datetime.datetime.now().time()
    # print time_in_range(eod_start,eod_stop,eod_now)
    #
    # if time_in_range(eod_start,eod_stop,eod_now):
    #     logger.info("Time to send EOD to pvoutput")
    #     pv_connection.add_output(date=date_now,
    #                              exported=total_wh_export,
    #                              import_peak=kwh_high,
    #                              import_offpeak=kwh_low,
    #                              comments=eod_cm)

    logger.debug("Release Lock - send pvoutput")
    lock.release()

    if daemon:
        t = threading.Timer(interval, thread_send_data_to_pvoutput,
                            [config, daemon])
        t.daemon = daemon
        t.start()



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

    config.add_section('PVOUTPUT')
    config.set('PVOUTPUT', 'enable', 'true')
    config.set('PVOUTPUT', 'api_key', '')
    config.set('PVOUTPUT', 'system_id', '')
    config.set('PVOUTPUT', 'interval', '300')

    path = os.path.expanduser(path)

    if os.path.isfile(path):
        if not query_yes_no("File already exists! continue?", default="no"):
            print ("OK! won't touch it!")
            return

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
    pvoutput_enable = config.getboolean('PVOUTPUT', 'enable')

    if pv_enable:

        logger.info("STARTING PV/VSN300 data Timer thread")
        thread_get_pv_data(config, args.daemon, args.simulate)

    if pvoutput_enable:

        logger.info("STARTING PV Output data Timer Thread")
        thread_send_data_to_pvoutput(config, args.daemon)

    if args.daemon:

        # keep main alive since we are launching daemon threads!
        while True:
            time.sleep(100)

if __name__ == "__main__":

    try:
        main()
    except KeyboardInterrupt:
        # quit
        print ("...Ctrl-C received!... exiting")
        sys.exit()