import threading
import os
import subprocess
import fcntl
import traceback


from utils import *
from error import *
from device import Device
from apkpackage import ApkPackage


class AppCrashWatcher(threading.Thread):
    def __init__(self, device, acw_lock, acw_crash_event, acw_ready_event):
        threading.Thread.__init__(self)
        self.device = device
        self.device_name = device.device_name
        self.lock = acw_lock
        self.crash_event = acw_crash_event
        self.ready_event = acw_ready_event
        self.isrunning = threading.Event()
        self.isrunning.clear()
        # self.isrunning = True
        self.idle_event = threading.Event()
        self.logger = device.logger.getChild('watchers.crash')

    def stop(self):
        # if self.stdout != None:
        try:
            self.stdout.close()
            self.adb_pipe.terminate()
            self.adb_pipe.poll()
        except:
            self.logger.error(traceback.format_exc())
        # self.isrunning = False
        self.isrunning.clear()
        self.ready_event.set()

    def set_current_app(self, app_name):
        self.lock.acquire()
        self.current_app_name = app_name
        self.lock.release()

    #TODO handle exception when failed to readline? or use apd_pipe_getline() to check pipe before read?
    def adb_pipe_clear_stdout(self):
        while(True):
            try:
                line = self.adb_pipe_getline()
                if line == '':
                    break
            except:
                self.logger.error(traceback.format_exc())

    #TODO call this in class.__init__(), call class.__init__ out of RunnerThread.__init__()
    #TODO check if init succeeded. 
    def adb_pipe_init(self):
        # run_cmdline('adb -s %s logcat -c' % self.device_name)
        self.device.adb_command('logcat', '-c', timeout=self.device.DEFAULT_TIMEOUT_CMD)
        # cmd = 'adb -s {0} logcat -s AndroidRuntime:E'.format(self.device_name)
        # cmd_array = shlex.split(cmd)
        # self.adb_pipe = subprocess.Popen(cmd_array,
        #                                  stderr=subprocess.DEVNULL, stdout=subprocess.PIPE, shell=False, bufsize=1)
        self.adb_pipe = self.device.adb_command('logcat', '-s AndroidRuntime:E', run_async=True, bufsize=1)
        self.stdout = self.adb_pipe.stdout
        f_flag = fcntl.fcntl(self.stdout, fcntl.F_GETFL)
        fcntl.fcntl(self.stdout, fcntl.F_SETFL, f_flag | os.O_NONBLOCK)

    def adb_pipe_check(self):
        if self.adb_pipe.poll() != None:
            self.logger.error('ADB subprocess failed, trying to init again.')
            self.isrunning.clear()
            self.adb_pipe_init()
            self.isrunning.set()

    def adb_pipe_getline(self):
        self.adb_pipe_check()
        return self.stdout.readline().decode(encoding='utf-8')
        
    #TODO handle stdout.read() exceptions
    def run(self):
        self.logger.info('AppCrashWatcher for ' + self.device_name + ' started.')
        self.adb_pipe_init()
        self.isrunning.set()
        # while (self.isrunning):
        while self.isrunning.is_set():
            self.adb_pipe_clear_stdout()
            self.ready_event.wait()
            # if self.isrunning == False:
            if not self.isrunning.is_set():
                self.adb_pipe.terminate()
                break
            self.crash_event.clear()
            current_app = self.current_app_name
            # while self.ready_event.is_set() and self.isrunning:
            while self.ready_event.is_set() and self.isrunning.is_set():
                while (True):
                    try:
                        line = self.adb_pipe_getline()
                        if line == '':
                            break
                        if 'E AndroidRuntime: FATAL EXCEPTION:' in line:
                            next_line = self.adb_pipe_getline()
                            if self.current_app_name in next_line:
                                # print('Decected app crash %s.' % current_app)
                                self.crash_event.set()
                                self.ready_event.clear()
                                break
                    except:
                        self.logger.error(traceback.format_exc())
                self.idle_event.wait(timeout=0.5)
        self.logger.info('AppCrashWatcher for ' + self.device_name + ' stopped.')


class RunnerThread(threading.Thread):
    # TODO: 出现一次超时，则立刻放弃此手机。
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
    ERR_LAUNCH = -5
    glk_getapk = threading.Lock()

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
        self.wait_event = gev_wait_event  # global wait event
        self.result_writer = result_writer
        self.device = Device(self.device_name, config, thread=self)
        self.running_time = config['running_time']
        self.gev_stop = gev_stop
        self.gev_stop.clear()
        self.gev_no_more_apk = gev_no_more_apk
        self.gev_no_more_apk.clear()
        self.logger = self.device.logger
        self.acw_thread = AppCrashWatcher(
            self.device, self.acw_lock, self.acw_crash_event, self.acw_ready_event)
        self.do_cleaning = True

    def run(self):
        self.logger.info('Runner thread for {0} started.'.format(self.device_name))
        try:
            self.logger.info('Init device')
            self.device.init_device()
            # TODO 如果初始化失败，push进去的文件可能清理不干净。
        except DeviceGetCpuArchError as e:
            self.logger.error('Failed to get CPU Architecture.')
            return
        except DeviceGetNetIfError as e:
            self.logger.error('Failed to get net interface.')
            return
        except DeviceInitError as e:
            self.logger.error('Init failed: ' + str(e))
            self.device.clean_device()
            return
        except RootPrivError as e:
            self.logger.error('No root shell.')
            return
        except DeviceApkBatchUninstallFailHandleError as e:
            self.logger.error('Failed to clean 3rd party apps: ' + str(e))
            return
        self.result_writer.register_device(self.device)
        capture_path = self.config['remote_cap_dir']
        self.acw_thread.start()
        self.logger.info('AppCrashWatcher start requested.')
        self.is_running = True
        item = None # APK package item
        try:
            while self.is_running and not self.gev_stop.is_set():
                self.logger.info('Getting an APK item from queue...')
                self.glk_getapk.acquire()
                if (self.gev_no_more_apk.is_set()) and (self.queue.empty()):
                    item = None
                else:
                    item = self.queue.get()
                self.glk_getapk.release()
                # Dirty hack:
                # The code here is to make it possible to run as a daemon. Remote server can
                # add apk files to the queue untimely, and make it can be terminated at
                # any time.
                # 
                # 此处的代码是为了兼容长时间持续运行而设计。远端服务器可以不定期地向队列中添加待测的apk文件，
                # 同时使之可以随时被结束。
                #
                # queue.get() should be block, and it also blocks checking the is_running flag.
                # When we should stop the thread, send a None object to enforce the queue.get()
                # method go on and let the thread check flag.
                #
                # queue.get() 会阻塞线程并阻止线程继续迭代检查 is_running 标志。当程序要结束此线程时，应当
                # 向队列中放入一个 None 对象，来结束 queue.get() 的阻塞。
                #
                #  When there are more than one threads consuming a unique queue, single None 
                # object in queue only can unblock 1 thread while other threads will keep 
                # blocked and won't exit. Thus if there are n threads and they all consume one
                # unique queue, we should put at least n None objects into the queue, or put 
                # the None object back into the queue when any thread got an None object to pass
                # it to next consumer thread.
                # 
                # 如果多个线程全部同时从1个队列中取数据，则1个None对象只能解除1个线程的阻塞状态，而其他线程则
                # 保持阻塞状态、无法退出。在此情况下，如果共有n个线程我们就需要向队列中插入至少n个None对象。
                # 或者，当某一线程获取到了一个None对象时，则将None对象放回到队列中，从而将其传递给下一个线程。
                if item == None:
                    self.logger.info('Queue is empty, break.')
                    self.queue.put(None)
                    break
                self.logger.info('Got APK item {0}({1})@{2}.'.format(item['pkg_name'], item['app_label'], item['apk_path']))
                self.device.check_netif()
                self.logger.info('Network interface OK: {0}'.format(self.device.netif))
                status_flag = self.STATUS_NOT_INSTALLED
                error_flag = 0
                db_flag = 'NULL'
                try:
                    item.device = self.device
                    self.logger.info('Installing: {0}({1})@{2}.'.format(item['pkg_name'], item['app_label'], item['apk_path']))
                    self.device.install_apk_local(item)
                    self.logger.info('APK installed.')
                    status_flag = self.STATUS_INSTALLED
                    self.acw_thread.set_current_app(item['pkg_name'])
                    self.logger.info('AppCrashWatcher activate requested.')
                    self.acw_thread.isrunning.wait(timeout=10)
                    if not self.acw_thread.isrunning.is_set():
                        raise CommandTimeout('AppCrashWatcher is not responding...')
                        self.do_cleaning = False
                    self.acw_ready_event.set()
                    # set capture env
                    # start caputre
                    pcap_file_name = self.result_writer.generate_pcap_name(
                        device=self.device, apk=item)
                    capture_file_path = '%s/%s' % (capture_path, pcap_file_name)
                    self.logger.info('.pcap file: ' + capture_file_path)
                    self.device.adb_run_remote_cmdline('mkdir -p %s' % (capture_path))
                    if self.gev_stop.is_set():
                        raise TestbenchInterruptedError
                    self.logger.info('tcpdump started.')
                    self.pipe = self.device.start_tcpdump_pipe(
                        self.device.netif, capture_file_path)
                    # BUG Program don't know if tcpdump is alive.
                    status_flag = self.STATUS_WATCH_EXEC
                    self.device.launch_app(item)
                    self.logger.info('Launched: {0}({1})@{2}.'.format(item['pkg_name'], item['app_label'], item['apk_path']))
                    status_flag = self.STATUS_APP_LAUNCHED
                    self.logger.info('Waiting for crash event...')
                    self.acw_crash_event.wait(timeout=10)
                    self.acw_ready_event.clear()
                    traverse_tag = 'None'
                    if (self.acw_crash_event.is_set()):
                        raise DeviceApkRuntimeError(apk_info = item, device=self)
                    else:
                        self.logger.info('No crash, trigger started.')
                        try:
                            traverse_tag = 'Manual'
                            if self.config['trigger'] == 1:  # Monkey
                                traverse_tag = 'Monkey'
                                self.device.launch_monkey(
                                    item['pkg_name'], self.config['monkey_ops'])
                            elif self.config['trigger'] == 2:  # UIAutomator
                                traverse_tag = 'UIAutomator'
                                self.device.launch_uiautomator()
                                self.wait_event.wait(timeout=self.running_time)  # capture time
                            else:  # Manual
                                self.wait_event.wait(timeout=self.running_time)  # capture time
                            status_flag = self.STATUS_UIAUTO_START
                            self.logger.info('Capture finished with ' + traverse_tag + '.')
                        except (DeviceRunMonkeyError, DeviceRunUiautomatorError) as e:
                            # warn without handling.
                            self.logger.error('Failed to run {}.'.format(traverse_tag))
                        # item['traverse_tag'] = traverse_tag
                        item['traverse_tag'] = self.config['trigger']
                        status_flag = self.STATUS_FINISHED
                        if self.config['trigger'] == 1:  # Monkey
                            db_flag = self.result_writer.FLAG_MONKEY_OK
                        elif self.config['trigger'] == 2:  # UIAutomator
                            db_flag = self.result_writer.FLAG_UIAUTOMATOR_OK
                        else:  # Manual
                            db_flag = self.result_writer.FLAG_MANUAL_OK
                except DeviceApkInstallError as e:
                    # TODO: sometimes this failure is recoverable!!!!
                    self.logger.error('Failed to install: ' + str(e))
                    error_flag = self.ERR_INSTALL
                    db_flag = self.result_writer.FLAG_INSTALL_FAIL
                    # TODO: Handle other errors
                    if e.errtype == 'INSTALL_FAILED_INSUFFICIENT_STORAGE':
                        raise e
                except DeviceApkLaunchError:
                    self.logger.error('Failed to launch: {0}({1})@{2}.'.format(item['pkg_name'], item['app_label'], item['apk_path']))
                    error_flag = self.ERR_LAUNCH
                    db_flag = self.result_writer.FLAG_LAUNCH_FAIL
                except DeviceApkRuntimeError as e:
                    self.logger.error('Crash detected.')
                    error_flag = self.ERR_CRASH
                    db_flag = self.result_writer.FLAG_CRASH
                except DeviceNetIfDown as e:
                    self.logger('Network interface is down.')
                    error_flag = self.ERR_NETIFDOWN
                    # Interrupt when net is down.
                    self.is_running = False
                finally:
                    # Nothing can be cleaned when install failed.
                    if status_flag < self.STATUS_INSTALLED:
                        pass
                    else:
                        # TODO Do following 3 ops only when flag is set to STATUS_WATCH_EXEC or bigger value
                        # TODO Handle adb pull error, 防止pull失败时继续向下执行产生异常。
                        self.logger.info('Killing all capture processes...')
                        self.device.clean_capture_process(self.pipe)
                        if error_flag != self.ERR_CRASH:
                            self.wait_event.wait(timeout=3)
                        self.logger.info('Pulling captured pcap file...')
                        if status_flag >= self.STATUS_WATCH_EXEC:
                            try:
                                self.device.adb_run_remote_su_cmdline('sync', timeout=self.device.DEFAULT_TIMEOUT_CMD)
                                if not self.device.test_file_exists(capture_file_path):
                                    raise DevicePcapNotExist(path=capture_file_path, device=self)
                                # (1) 'tcpdump' still alive when app crash.
                                #     In this case, this pcap file should be abandoned.
                                # (2) When network is down, 'tcpdump' don't produce any file.
                                #     Treat as normal and it will pull nothing.
                                if error_flag != self.ERR_CRASH:
                                    self.device.adb_pull(
                                        capture_file_path, self.config['output_dir'] + '/')
                                self.logger.info('Capture file pulled to ' + self.config['output_dir'])
                                # TODO: set file ready flag
                            except DeviceFileNotExist:
                                status_flag = self.STATUS_PCAP_NOTEXIST
                                error_flag = self.ERR_PCAP_NOTEXIST
                                self.logger.error('.pcap file not exist.')
                            except AdbPullError as e:
                                pass # TODO handle it
                            except AdbError as e:
                                self.logger.error('Unhandled ADB error.')
                                self.logger.error(traceback.format_exc())
                        try:
                            self.logger.info('Cleaning capture directory...')
                            self.device.adb_run_remote_cmdline(
                                'rm -rf %s' % (capture_file_path))
                        except:
                            self.logger.warning('Failed to clean pcap file')
                        # clean env
                        self.logger.info('Cleaning 3rd party apps...')
                        self.device.clean_3rdparty_apps()
                    try:
                        self.logger.info('Writing result...')
                        # TODO: check file ready flag
                        # TODO: 写入失败会导致线程阻塞
                        if (status_flag == self.STATUS_FINISHED and error_flag != self.ERR_PCAP_NOTEXIST):
                            self.result_writer.report_success(
                                self.device, item, pcap_file_name, db_flag)
                        elif error_flag in [self.ERR_INSTALL, self.ERR_CRASH]:
                            self.result_writer.report_fail(self.device, item, db_flag)
                        elif error_flag == self.ERR_PCAP_NOTEXIST:
                            #TODO What to do when ERR_PCAP_NOTEXIST happens?
                            pass
                    except Exception as e:
                        # TODO: Handle write failure
                        self.logger.error('Failed to write result.')
                        self.logger.error(traceback.format_exc())
        except DeviceNetIfDown as e:
            self.logger.error('Network interface is down and failed to recover.')
        except Exception as e:
            self.logger.error(traceback.format_exc())
        finally:
            self.is_running = False
            self.logger.info('Requesting AppCrashWatcher to stop...')
            self.acw_thread.stop()
            if self.do_cleaning:
                self.logger.info('Cleaning 3rd party apps...')
                if item != None:
                    self.device.clean_3rdparty_apps()
                self.logger.info('Cleaning device environment...')
                self.device.clean_device()
                self.logger.info('Runner thread for {0} stopped.'.format(self.device_name))