import datetime
import fcntl
import json
import logging
import os
import re
import shlex
import signal
import subprocess
import threading
import time
from queue import Queue

import pymysql

import result_writer
from apkpackage import ApkPackage
from device import Device
from error import *
from utils import *
from runner import *

logger = logging.getLogger(name=__name__)
no_more_apk = threading.Event()
stopped = threading.Event()
global_wait = threading.Event()




class ApkAnalyzerThread(threading.Thread):
    def __init__(self, path, queue_list, config, result_writer, gev_stop, gev_no_more_apk):
        threading.Thread.__init__(self)
        self.path = path
        self.queue_list = queue_list
        self.config = config
        self.result_writer = result_writer
        self.gev_stop = gev_stop
        self.gev_stop.clear()
        self.gev_no_more_apk = gev_no_more_apk
        self.gev_no_more_apk.clear()
        self.logger = logging.getLogger(name=__name__)

    def report_error(self, path, md5):
        item = dict()
        item['apk_path'] = path
        item['md5'] = md5
        flag = self.result_writer.FLAG_BROKEN
        self.result_writer.report_fail(None, item, flag)

    def run(self):
        '''
         zgkom
         让同一台设备在规定时间，只对同一类apk采集
         :return:
        '''
        dirs_name = os.listdir(self.path)
        for dir_name in dirs_name:
            dir_path = os.path.join(self.path, dir_name)
            files = os.listdir(dir_path)
            temp_queue = Queue()
            for item in files:
                md5 = 'NONE'
                item = os.path.join(dir_path, item)
                if self.gev_stop.is_set():
                    break
                if item[-4:] != '.apk':
                    continue
                try:
                    md5 = get_md5_from_path(item)
                    info = ApkPackage(item, self.config)
                    temp_queue.put(info)
                except (ApkPkgParseError, Exception) as e:
                    path = item
                    self.logger.error('Failed to parse apk ' + item)
                    self.report_error(item, md5)
            temp_queue.put(None)
            self.queue_list.append(temp_queue)
            self.gev_no_more_apk.set()




class ApkDispatcherThread(threading.Thread):
    NotImplemented


def sigint_handler(signum, frame):
    global device_thread_list
    global stopped
    stopped.set()
    global_wait.set()


if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGHUP, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    logging.basicConfig(
        level=logging.INFO, format='[%(asctime)s][%(name)s][%(levelname)s] %(message)s')

    global device_thread_list
    device_thread_list = list()
    apk_path_list = list()
    apk_queue_list = list()
    queue_list = list()
    self_dir= os.path.dirname(os.path.abspath(__file__))
    config_file = open(os.path.join(self_dir, 'config.json'))
    config = json.load(config_file)
    config['current_dir'] = self_dir
    #config['bin_path']['adb'] = whereis_adb()
    # check_config(config)
    config_file.close()

    log_lock = threading.Lock()
    sql_conn = pymysql.connect(host='202.194.67.219', user='root5', passwd='root', db='ybn_v2')
    result_writer = result_writer.DbResultWriter(config, sql_conn, log_lock)
    # log_path = os.path.join(config['output_dir'], 'capture_log.sql')
    # log_file = open(log_path, mode='a')
    # result_writer = result_writer.SqlTextResultWriter(
    #     config, log_file, log_lock)

    check_path(config['output_dir'])
    ret, device_list = Device.list_device_available()
    if ret != 0:
        exit()
    analyzer_thread = ApkAnalyzerThread(
        config['input_dir'], apk_queue_list, config, result_writer, stopped, no_more_apk)
    analyzer_thread.start()

    # TODO dispatcher_thread = ApkDispatcherThread(input_queue, output_queues)
    index = 0
    for item in device_list:
        t = RunnerThread(item, apk_queue_list[index], config,
                         result_writer, global_wait, stopped, no_more_apk)
        device_thread_list.append(t)
        t.start()
        index = index + 1

    analyzer_thread.join()
    # TODO dispatcher_thread.join()
    for item in device_thread_list:
        item.join()

    
    # log_file.close()
    sql_conn.close()
