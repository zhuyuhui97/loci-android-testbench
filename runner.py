import threading
import os
import subprocess
import fcntl
import traceback


from utils import *
from error import *
from device import Device


class AppCrashWatcher(threading.Thread):
    def __init__(self, device, acw_lock, acw_crash_event, acw_ready_event):
        threading.Thread.__init__(self)
        self.device = device
        self.device_name = device.device_name
        self.lock = acw_lock
        self.crash_event = acw_crash_event
        self.ready_event = acw_ready_event
        self.isrunning = True
        self.idle_event = threading.Event()

    def stop(self):
        # if self.stdout != None:
        try:
            self.stdout.close()
            self.adb_pipe.terminate()
            self.adb_pipe.poll()
        except:
            pass
        self.isrunning = False
        self.ready_event.set()

    def set_current_app(self, app_name):
        self.lock.acquire()
        self.current_app_name = app_name
        self.lock.release()

    def clear_stdout(self):
        while(True):
            try:
                line = self.stdout.readline().decode()
                if line == '':
                    break
            except:
                pass

    def run(self):
        run_cmdline('adb -s %s logcat -c' % self.device_name)
        cmd = 'adb -s {0} logcat -s AndroidRuntime:E'.format(self.device_name)
        cmd_array = shlex.split(cmd)
        self.adb_pipe = subprocess.Popen(cmd_array,
                                         stderr=subprocess.DEVNULL, stdout=subprocess.PIPE, shell=False, bufsize=1)
        self.stdout = self.adb_pipe.stdout
        f_flag = fcntl.fcntl(self.stdout, fcntl.F_GETFL)
        fcntl.fcntl(self.stdout, fcntl.F_SETFL, f_flag | os.O_NONBLOCK)
        while (self.isrunning):
            self.clear_stdout()
            self.ready_event.wait()
            if self.isrunning == False:
                self.adb_pipe.terminate()
                return
            self.crash_event.clear()
            # self.lock.acquire()
            current_app = self.current_app_name
            # self.lock.release()
            while self.ready_event.is_set() and self.isrunning:
                while (True):
                    try:
                        line = self.stdout.readline().decode(encoding='gbk')
                        if line == '':
                            break
                        if 'E AndroidRuntime: FATAL EXCEPTION:' in line:
                            next_line = self.stdout.readline().decode()
                            if self.current_app_name in next_line:
                                print('Decected app crash %s.' % current_app)
                                self.crash_event.set()
                                self.ready_event.clear()
                                break
                    except:
                        pass
                self.idle_event.wait(timeout=0.5)


class RunnerThread(threading.Thread):
    STATUS_NOT_INSTALLED = 0
    STATUS_INSTALLED = 1
    STATUS_WATCH_EXEC = 2
    STATUS_APP_LAUNCHED = 3
    STATUS_UIAUTO_START = 4
    STATUS_FINISHED = 5
    STATUS_REMOVED = 6
    STATUS_PCAP_NOTEXIST = 5

    ERR_INSTALL = -1  # Install failed
    ERR_CRASH = -2  # APP crash detected
    ERR_NETIFDOWN = -3  # Network interface is down
    ERR_PCAP_NOTEXIST = -4 # Pcap file not exist on the phone

    def __init__(self, device_name, queue, config, result_writer, gev_wait_event, gev_stop, gev_no_more_apk):
        threading.Thread.__init__(self)
        self.device_name = device_name
        self.queue = queue
        self.is_running = False
        self.config = config
        self.pipe = None
        #self.log_file = logfile
        #self.log_lock = loglock
        self.acw_lock = threading.Lock()
        self.acw_crash_event = threading.Event()
        self.acw_ready_event = threading.Event()
        self.acw_thread = AppCrashWatcher(
            self, self.acw_lock, self.acw_crash_event, self.acw_ready_event)
        self.wait_event = gev_wait_event  # global wait event
        self.result_writer = result_writer
        self.device = Device(self.device_name, config, thread=self)
        self.running_time = config['running_time']
        self.gev_stop = gev_stop
        self.gev_stop.clear()
        self.gev_no_more_apk = gev_no_more_apk
        self.gev_no_more_apk.clear()
        self.logger = self.device.logger

    def run(self):
        try:
            self.device.init_device()
        except DeviceGetPropError as e:
            self.logger.error('Init failed. Stopping thread for %s' %
                         (self.device_name))
            self.logger.error(traceback.format_exc())
            return
        except DeviceInitError as e:
            cmd = e.cmd
            self.logger.error('Init failed. Stopping thread for %s' %
                         (self.device_name))
            self.logger.error(traceback.format_exc())
            self.device.clean_device()
            return
        except RootPrivError as e:
            self.logger.error('No root priv. Stopping thread for %s' %
                         (self.device_name))
            self.logger.error(traceback.format_exc())
            return
        capture_path = self.config['remote_cap_dir']
        self.acw_thread.start()
        self.is_running = True
        item = None # APK package item
        try:
            while self.is_running and not self.gev_stop.is_set():
                if (self.gev_no_more_apk.is_set()) and (self.queue.empty()):
                    break
                item = self.queue.get()
                self.device.check_netif()
                # Dirty hack:
                # queue.get() should be block, and it also blocks checking the is_running flag.
                # When we should stop the thread, send a None object to enforce the queue.get()
                # method go on and let the thread check flag.
                if item == None:
                    break
                status_flag = self.STATUS_NOT_INSTALLED
                error_flag = 0
                db_flag = 'NULL'
                try:
                    item.device = self.device
                    ret, output = self.device.install_apk_local(item)
                    status_flag = self.STATUS_INSTALLED
                    # HACK self.acw_lock.acquire() cause a deadlock
                    self.acw_thread.set_current_app(item['pkg_name'])
                    # self.acw_lock.release()
                    self.acw_ready_event.set()
                    # set capture env
                    # start caputre
                    pcap_file_name = self.result_writer.generate_pcap_name(
                        device=self.device, apk=item)
                    capture_file_path = '%s/%s' % (capture_path, pcap_file_name)
                    self.device.adb_run_remote_cmdline(
                        'mkdir -p %s' % (capture_path))
                    if self.gev_stop.is_set():
                        raise TestbenchInterruptedError
                    # run_cmdline('mkdir -p %s/%s' %
                    #             (config.CFG_PCAP_OUTPUT_PATH, item['apk_path_parents']))
                    self.pipe = self.device.start_tcpdump_pipe(
                        self.device.netif, capture_file_path)
                    # BUG Program don't know if tcpdump is alive.
                    status_flag = self.STATUS_WATCH_EXEC
                    try:
                        self.device.launch_app(item)
                        status_flag = self.STATUS_APP_LAUNCHED
                    except DeviceApkLaunchError:
                        pass
                    self.acw_crash_event.wait(timeout=5)
                    self.acw_ready_event.clear()
                    traverse_tag = 'None'
                    if (self.acw_crash_event.is_set()):
                        raise DeviceApkRuntimeError(device=self)
                    else:
                        try:
                            traverse_tag = 'Manual'
                            if self.config['trigger'] == 1:  # Monkey
                                traverse_tag = 'Monkey'
                                self.device.launch_monkey(
                                    item['pkg_name'], self.config['monkey_ops'])
                            elif self.config['trigger'] == 2:  # UIAutomator
                                traverse_tag = 'UIAutomator'
                                self.device.launch_uiautomator()
                                self.wait_event.wait(
                                    timeout=self.running_time)  # capture time
                            else:  # Manual
                                self.wait_event.wait(
                                    timeout=self.running_time)  # capture time
                            status_flag = self.STATUS_UIAUTO_START
                            self.logger.info('captured')
                        except (DeviceRunMonkeyError, DeviceRunUiautomatorError) as e:
                            # warn without handling.
                            self.logger.error('Failed to run {}.'.format(traverse_tag))
                        item['traverse_tag'] = traverse_tag
                        status_flag = self.STATUS_FINISHED
                        if self.config['trigger'] == 1:  # Monkey
                            db_flag = self.result_writer.FLAG_MONKEY_OK
                        elif self.config['trigger'] == 2:  # UIAutomator
                            db_flag = self.result_writer.FLAG_UIAUTOMATOR_OK
                        else:  # Manual
                            db_flag = self.result_writer.FLAG_MANUAL_OK
                except DeviceApkInstallError as e:
                    self.logger.error('Failed to install')
                    error_flag = self.ERR_INSTALL
                    db_flag = self.result_writer.FLAG_INSTALL_FAIL
                except DeviceApkRuntimeError as e:
                    self.logger.error('Crash detected')
                    error_flag = self.ERR_CRASH
                    db_flag = self.result_writer.FLAG_CRASH
                except DeviceNetIfDown as e:
                    self.logger('Network interface is down')
                    error_flag = self.ERR_NETIFDOWN
                    # Interrupt when net is down.
                    self.is_running = False
                finally:
                    # Nothing can be cleaned when install failed.
                    if status_flag < self.STATUS_INSTALLED:
                        pass
                    else:
                        # TODO Do following 3 ops only when flag is set to STATUS_WATCH_EXEC or bigger value
                        self.device.clean_capture_process(self.pipe)
                        if error_flag != self.ERR_CRASH:
                            self.wait_event.wait(timeout=3)
                        if status_flag >= self.STATUS_WATCH_EXEC:
                            try:
                                if not self.device.test_file_exists(capture_file_path):
                                    raise DevicePcapNotExist(self, path=capture_file_path)
                                # (1) 'tcpdump' still alive when app crash.
                                #     In this case, this pcap file should be abandoned.
                                # (2) When network is down, 'tcpdump' don't produce any file.
                                #     Treat as normal and it will pull nothing.
                                if error_flag != self.ERR_CRASH:
                                    self.device.adb_pull(
                                        capture_file_path, self.config['output_dir'] + '/')
                            except DeviceFileNotExist:
                                status_flag = self.STATUS_PCAP_NOTEXIST
                                error_flag = self.ERR_PCAP_NOTEXIST
                                logger.error('.pcap file not exist')
                                logger.error(traceback.format_exc())
                            except AdbError as e:
                                logger.error(traceback.format_exc())
                        try:
                            self.device.adb_run_remote_cmdline(
                                'rm -rf %s' % (capture_file_path))
                        except:
                            pass
                        # clean env
                        try:
                            ret, output = self.device.remove_apk_local(item)
                        except DeviceApkUninstallError:
                            self.logger.error('%s: Failed to remove app %s(%s):%s' % (
                                self.device_name, item['app_label'], item['pkg_name'], output))
                    try:
                        if (status_flag == self.STATUS_FINISHED and error_flag != self.ERR_PCAP_NOTEXIST):
                            self.result_writer.report_success(
                                self.device, item, pcap_file_name, db_flag)
                        elif error_flag in [self.ERR_INSTALL, self.ERR_CRASH]:
                            self.result_writer.report_fail(self.device, item, db_flag)
                        elif error_flag == self.ERR_PCAP_NOTEXIST:
                            #TODO What to do when ERR_PCAP_NOTEXIST happens?
                            pass
                    except Exception as e:
                        logger.error('Failed to write result')
                        logger.error(traceback.format_exc())
        except (Exception) as e:
            logger.error(traceback.format_exc())
            if item != None:
                try:
                    ret, output = self.device.remove_apk_local(item)
                except DeviceApkUninstallError:
                    self.logger.error('%s: Failed to remove app %s(%s):%s' % (
                        self.device_name, item['app_label'], item['pkg_name'], output))
        finally:
            self.acw_thread.stop()
            self.is_running = False
            self.device.clean_device()