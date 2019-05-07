import logging
import os
import re
import shlex
import signal
import subprocess
import time

from error import *
from utils import *


class Device(object):

    def __init__(self, device_name, config, thread=None):
        self.logger = logging.getLogger('Device/%s' % device_name)
        self.device_name = device_name
        self.global_config = config
        self.run_thread = thread
        self.cmd_su_prefix = ''
        self.build_prop = dict()
        self.uiauto_pipe = None
        # self.init_device() Do it outside!

    @classmethod
    def scan_devices_available(cls, config):
        device_list = list()
        ret, device_list_txt = cls.list_device_available()
        for item in device_list_txt:
            item_obj = cls(item, config)
            device_list.append(item_obj)
        return device_list

    def adb_run_remote_cmdline(self, cmd):
        cmdline = 'adb -s {0} shell \"{1}\"'.format(self.device_name, cmd)
        return run_cmdline(cmdline)

    def adb_run_remote_su_cmdline(self, cmd):
        if self.cmd_su_prefix != '':
            cmd = '{0} \'{1}\''.format(self.cmd_su_prefix, cmd)
        return self.adb_run_remote_cmdline(cmd)

    def adb_push(self, src_path, dst_path):
        return run_cmdline('adb -s %s push \'%s\' \'%s\'' % (self.device_name, src_path, dst_path))

    def adb_pull(self, src_path, dst_path):
        return run_cmdline('adb -s %s pull \'%s\' \'%s\'' % (self.device_name, src_path, dst_path))

    def pull_traffic(self, src_path, dest_path):
        ret, output = self.adb_run_remote_cmdline("ls %s" % src_path)
        if ret != 0:
            self.logger.error("")
            return ret
        res = output.split()
        for item in res:
            item = item.strip()
            item = src_path + '/' + item
            ret, output = self.adb_pull(item, dest_path)
            if ret != 0:
                self.logger.error("")
                return ret
        ret, output = self.adb_run_remote_cmdline("rm -rf \'%s/*\'" % src_path)
        return ret

    def install_apk_local(self, apk_info):
        device_name = self.device_name
        app_label = apk_info['app_label']
        apk_path = apk_info['apk_path']
        cmd = "adb -s %s install \'%s\'" % (device_name, apk_path)
        ret, output = run_cmdline(cmd)
        if ret != 0:
            info = "Failed to install %s(%s): %s" % (
                app_label, apk_path, output)
            raise DeviceApkInstallError(
                device=self, cmd=cmd, ret=ret, output=output, info=info)
        if (int(apk_info['pkg_target_sdkver']) >= 23) and (apk_info['pkg_target_sdkver'] != -1):
            apk_info.grant_permissions(self)
        return ret, output

    def launch_app(self, apk_info):
        # TODO Only launch first entry???
        pkg_name = apk_info['pkg_name']
        if len(apk_info['app_entries']) == 0:
            return
        app_entry = apk_info['app_entries'][0]
        cmd = "am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -n %s/%s" % (
            pkg_name, app_entry)
        ret, output = self.adb_run_remote_cmdline(cmd)
        if ret != 0:
            info = "Failed to launch app %s: %s" % (
                apk_info['app_label'], output)
            raise DeviceApkLaunchError(
                device=self, cmd=cmd, ret=ret, output=output, info=info)
        return ret, output

    def remove_apk_local(self, apk_info):
        device_name = self.device_name
        pkg_name = apk_info['pkg_name']
        cmd = "adb -s %s uninstall %s" % (device_name, pkg_name)
        ret, output = run_cmdline(cmd)
        if ret != 0:
            info = "Failed to remove %s: %s" % (pkg_name, output)
            raise DeviceApkUninstallError(
                device=self, cmd=cmd, ret=ret, output=output, info=info)
        return ret, output

    @classmethod
    def __list_device_all(cls):  # Show all android device connected to the PC.
        cmd = 'adb devices'
        ret, output = run_cmdline(cmd)
        if ret != 0:
            # logger.error('Error while getting device list. errno=%d' % ret)
            # return ret, None
            raise CmdListDeviceError(
                cmd=cmd, ret=ret, output=output, info='Error while getting device list.')
        tmplist = output.split('\n')
        tmplist.remove(tmplist[0])  # skip first line
        device_list = dict()
        for line in tmplist:
            if line.strip() != '':
                name = line.split()[0]
                status = line.split()[1]
                device_list[name] = status
        return ret, device_list

    @classmethod
    def list_device_available(cls):
        ret, all_list = cls.__list_device_all()
        device_list = dict()
        for item in all_list:
            if (all_list[item] == 'device'):
                device_list[item] = all_list[item]
        return ret, device_list

    def check_iptables(self):
        pass

    def get_device_cpu_arch(self):
        cmd = 'uname -m'
        ret, output = self.adb_run_remote_cmdline(cmd)
        if ret != 0:
            # self.logger.error('Failed to get cpu architecture of %s' %
            #              (self.device_name))
            # return None
            raise DeviceGetCpuArchError(
                device=self, cmd=cmd, ret=ret, output=output, info='Failed to get cpu architecture')
        return output

    def get_device_netif(self):
        cmd = 'dumpsys netstats'
        ret, output = self.adb_run_remote_cmdline(cmd)
        lines = output.split('\n')
        netif = None
        for i in range(len(lines)):
            if lines[i].strip() == 'Active interfaces:':
                netif = re.findall(r'iface=(.+?)\s', lines[i+1])
                break
        if (ret != 0) or (len(netif) == 0):
            # self.logger.error('Failed to get active network interface of %s' %
            #              (self.device_name))
            # return None
            raise DeviceGetNetIfError(
                device=self, cmd=cmd, ret=ret, output=output, info='Failed to get active network interface')
        return netif[0]

    def get_device_buildprop(self):
        flag = True
        cmd = 'getprop ro.product.brand'
        self.build_prop['brand'] = 'NULL'
        ret, output = self.adb_run_remote_cmdline(cmd)
        if output != '':
            self.build_prop['brand'] = output
        else:
            flag = False
        cmd = 'getprop ro.build.product'
        self.build_prop['product'] = 'NULL'
        ret, output = self.adb_run_remote_cmdline(cmd)
        if output != '':
            self.build_prop['product'] = output
        else:
            flag = False
        cmd = 'getprop ro.build.version.sdk'
        self.build_prop['sdkver'] = 'NULL'
        ret, output = self.adb_run_remote_cmdline(cmd)
        if output != '':
            self.build_prop['sdkver'] = output
        else:
            flag = False
        cmd = 'getprop ro.build.tags'
        self.build_prop['build_tags'] = 'NULL'
        ret, output = self.adb_run_remote_cmdline(cmd)
        if output != '':
            self.build_prop['build_tags'] = output
        else:
            flag = False
        self.device_tag = '{}/{}/{}'.format(self.build_prop['brand'],
                                            self.build_prop['product'], self.build_prop['sdkver'])
        if not flag:
            raise DeviceGetBuildPropError(self, info=self.device_tag)

    def get_device_ontop_activity(self):
        pass
        # dumpsys

    def check_netif(self):
        netif = None
        retry = 0
        while retry <= 3:
            try:
                netif = self.get_device_netif()
                if netif != self.netif and netif != None:
                    self.netif = netif
                    self.logger.warn('Active network interface changed.')
                break
            except DeviceGetNetIfError as e:
                self.adb_run_remote_cmdline('svc wifi enable')
                self.adb_run_remote_cmdline('svc data enable')
                retry = retry + 1
                self.run_thread.wait_event.wait(timeout=10)
        if netif == None:
            raise DeviceNetIfDown(self)



    def push_tcpdump(self):
        config = self.global_config
        local_bin_dir = config['local_bin_dir']
        bin_tcpdump = config['bin_tcpdump'][self.arch]
        remote_cap_dir = config['remote_cap_dir']
        remote_bin_dir = config['remote_bin_dir']
        if self.arch not in config['bin_tcpdump']:
            raise DevicePushTcpdumpError(device=self, info='No \'tcpdump\' binary for arch {0}'.format(self.arch))
        local_bin = os.path.join(config['current_dir'], local_bin_dir, bin_tcpdump)
        # TODO use remote_bin_path?
        dst_bin = '{0}/tcpdump'.format(remote_cap_dir)
        ret, output = self.adb_push(local_bin, dst_bin)
        if ret != 0:
            # self.logger.error('Failed to push tcpdump binary to %s: %s' %
            #              (self.device_name, output))
            # return ret
            raise DevicePushTcpdumpError( 
                device=self, src=local_bin, dst=dst_bin, output=output)
        cmd = 'mkdir {0}'.format(remote_bin_dir)
        ret, output = self.adb_run_remote_su_cmdline(cmd)
        cmd = 'cp {0}/tcpdump {1}/tcpdump'.format(remote_cap_dir, remote_bin_dir)
        ret, output = self.adb_run_remote_su_cmdline(cmd)
        if ret != 0:
            # self.logger.error('Failed to setup tcpdump binary to %s: %s' %
            #              (self.device_name, output))
            # return ret
            raise DeviceSetupTcpdumpError(
                device=self, cmd=cmd, ret=ret, output=output, info='Failed to setup tcpdump binary')
        cmd = 'rm {0}/tcpdump'.format(remote_cap_dir)
        self.adb_run_remote_cmdline(cmd)
        cmd = 'chmod +x {}/tcpdump'.format(remote_bin_dir)
        ret, output = self.adb_run_remote_su_cmdline(cmd)
        if ret != 0:
            # self.logger.error('Failed to setup tcpdump binary to %s: %s' %
            #              (self.device_name, output))
            # return ret
            raise DeviceSetupTcpdumpError(
                device=self, cmd=cmd, ret=ret, output=output, info='Failed to setup tcpdump binary')
        return 0

    def check_tcpdump(self):
        remote_bin_dir = self.global_config['remote_bin_dir']
        # TODO use remote_bin_path?
        cmd = '{0}/tcpdump --version'.format(remote_bin_dir)
        ret, output = self.adb_run_remote_su_cmdline(cmd)
        if ret != 0:
            #self.logger.error('Executable tcpdump is not configured properly.')
            raise DeviceSetupTcpdumpError(
                self, cmd=cmd, ret=ret, output=output, info='Executable tcpdump is not configured properly.')
        return ret

    def setup_tcpdump(self, local_bin_path, remote_bin_path):
        # TODO We assume all devices are ARM-based currently.
        # TODO Read executable file name from config.ini
        ret = self.push_tcpdump()
        ret = self.check_tcpdump()
        return 0

    def start_tcpdump_pipe(self, netif, capture_file_path):
        remote_bin_dir = self.global_config['remote_bin_dir']
        cmdline = ('adb -s {0} shell {4} {1}/tcpdump -i {2} -w {3}'.format(self.device_name, remote_bin_dir, netif, capture_file_path, self.cmd_su_prefix))
        self.logger.debug('[CMD]>%s' % cmdline)
        #args = shlex.split(cmdline)
        pipe = subprocess.Popen(cmdline, shell=True)
        return pipe

    def kill_remote_tcpdump(self, p):
        self.adb_run_remote_su_cmdline('killall tcpdump')
        if p != None:
            self.kill_tcpdump_pipe(p)

    def kill_tcpdump_pipe(self, p):
        p.terminate()
        ret = p.poll()
        if ret == None:
            p.kill()
        return p.poll()

    def push_uiautomator(self, local_bin):
        config = self.global_config
        local_bin_dir = config['local_bin_dir']
        bin_uaplugin = config['bin_uaplugin']
        remote_cap_dir = config['remote_cap_dir']
        remote_bin_dir = config['remote_bin_dir']
        dummymain_path = os.path.join(config['current_dir'], local_bin_dir, 'uaplugin_dummymain.apk')
        uaplugin_path = os.path.join(config['current_dir'], local_bin_dir, 'uaplugin_test.apk')
        cmd = 'adb install -t -r \"' + dummymain_path + '\"'
        ret, output = run_cmdline(cmd)
        if ret != 0:
            raise DeviceSetupUiautomatorError(
                device=self, cmd=cmd, ret=ret, output=output, info='Failed to setup uiautomator')
        cmd = 'adb install -t -r \"' + uaplugin_path + "\""
        ret, output = run_cmdline(cmd)
        if ret != 0:

            raise DeviceSetupUiautomatorError(
                device=self, cmd=cmd, ret=ret, output=output, info='Failed to setup uiautomator')
        # # TODO use remote_bin_path?
        # local_bin = os.path.join(config['current_dir'], local_bin_dir, bin_uaplugin)
        # dst_bin = '{0}/{1}'.format(remote_cap_dir, bin_uaplugin)
        # ret, output = self.adb_push(local_bin, dst_bin)
        # if ret != 0:
        #     # self.logger.error('Failed to push uiautomator binary to %s: %s' %
        #     #              (self.device_name, output))
        #     # return ret, output
        #     raise DevicePushUiautomatorError(
        #         device=self, src=local_bin, dst=dst_bin, output=output)
        # cmd = 'mkdir {0}'.format(remote_bin_dir)
        # ret, output = self.adb_run_remote_su_cmdline(cmd)
        # cmd = 'cp {0}/{2} {1}/{2}'.format(remote_cap_dir, remote_bin_dir, bin_uaplugin)
        # ret, output = self.adb_run_remote_su_cmdline(cmd)
        # if ret != 0:
        #     # self.logger.error(' Failed to setup uiautomator binary to %s: %s' %
        #     #              (self.device_name, output))
        #     # return ret, output
        #     raise DeviceSetupUiautomatorError(
        #         device=self, cmd=cmd, ret=ret, output=output, info='Failed to setup uiautomator')
        # cmd = 'rm {0}/{1}'.format(remote_cap_dir, bin_uaplugin)
        # self.adb_run_remote_cmdline(cmd)
        # cmd = 'chmod +x {0}/{1}'.format(remote_bin_dir, bin_uaplugin)
        # ret, output = self.adb_run_remote_su_cmdline(cmd)
        # if ret != 0:
        #     # self.logger.error('Failed to setup uiautomator binary to %s: %s' %
        #     #              (self.device_name, output))
        #     # return ret, output
        #     raise DeviceSetupUiautomatorError(
        #         device=self, cmd=cmd, ret=ret, output=output, info='Failed to setup uiautomator')
        return 0, None


    def launch_uiautomator(self):
        # bin_uaplugin = self.global_config['bin_uaplugin']
        # remote_bin_dir = self.global_config['remote_bin_dir']
        # cmd = "uiautomator runtest {0}/{1} --nohup -c com.jikexueyuan.Test#traversalAPK".format(remote_bin_dir, bin_uaplugin)
        # ret, output = self.adb_run_remote_cmdline(cmd)
        # if ret != 0:
        #     #self.logger.error('Error while launching uiautomator. errno=%d' % ret)
        #     raise DeviceRunUiautomatorError(
        #         device=self, cmd=cmd, ret=ret, output=output, info='Error while launching uiautomator.')
        # return ret
        cmd = 'adb shell am instrument -w -r -e debug false cn.edu.ujn.loci.uaplugin2.test/androidx.test.runner.AndroidJUnitRunner'
        cmd_line = shlex.split(cmd)
        self.uiauto_pipe = subprocess.Popen(cmd_line)
        # TODO test it!

    def kill_remote_uiautomator(self):
        # self.adb_run_remote_su_cmdline('killall uiautomator')
        self.uiauto_pipe.terminate()
        self.uiauto_pipe.poll()

    def launch_monkey(self, pkg_name, op_count):
        #cmd = "\'nohup monkey -p %s --throttle 400 -v-v-v %d >/dev/null 2>&1 &\'" % (pkg_name, op_count)
        cmd = "monkey -p %s --throttle 400 -v-v-v %d" % (pkg_name, op_count)
        ret, output = self.adb_run_remote_cmdline(cmd)
        if ret != 0:
            #self.logger.error('Error while launching uiautomator. errno=%d' % ret)
            raise DeviceRunMonkeyError(
                device=self, cmd=cmd, ret=ret, output=output, info='Error while launching uiautomator.')
        return ret
        # TODO test it!

    def kill_remote_monkey(self):
        self.adb_run_remote_su_cmdline(
            'killall com.android.commands.monkey')
        # （:-o）

    def test_file_exists(self, filepath):
        EXIST_FLAG = 'YES'
        cmd = "if [ -e {0} ]; then echo {1}; fi".format(escape_path(filepath), EXIST_FLAG)
        ret, output = self.adb_run_remote_su_cmdline(cmd)
        if ret != 0:
            raise AdbError(device=self, cmd=cmd, ret=ret)
        return (output == EXIST_FLAG)

    def init_capture_dirs(self):
        pass

    ADBROOT_BUILDTAGS = ['test-keys', 'userdebug', 'eng']
    def init_root_priv(self):
        run_cmdline('adb -s {0} root'.format(self.device_name))
        ret, output = self.adb_run_remote_su_cmdline('whoami')
        logging.debug(output)
        if output == 'root':
            return
        self.cmd_su_prefix = 'su -c'
        ret, output = self.adb_run_remote_su_cmdline('whoami')
        logging.debug(output)
        if output != 'root':
            raise RootPrivError(self)
        return
        # TODO Check root priv

    def init_device(self):
        try:
            self.get_device_buildprop()
        except DeviceGetBuildPropError as e:
            pass  # Not handled
        self.init_root_priv()
        self.init_capture_dirs()
        self.kill_remote_tcpdump(None)
        local_bin_path = os.path.join(self.global_config['current_dir'], self.global_config['local_bin_dir'])
        self.arch = self.get_device_cpu_arch()
        self.netif = self.get_device_netif()

        ret = self.setup_tcpdump(local_bin_path, None)
        ret, output = self.push_uiautomator(local_bin_path + '/uaplugin.jar')
        return 0

    def clean_bin_dirs(self):
        remote_cap_dir = self.global_config['remote_cap_dir']
        remote_bin_dir = self.global_config['remote_bin_dir']
        self.adb_run_remote_cmdline('rm -rf {0}/*'.format(remote_bin_dir))

    def clean_capture_dirs(self):
        remote_cap_dir = self.global_config['remote_cap_dir']
        remote_bin_dir = self.global_config['remote_bin_dir']
        self.adb_run_remote_cmdline('rm -rf {0}/*'.format(remote_cap_dir))

    def clean_capture_process(self, tcpdump_pipe=None):
        self.kill_remote_tcpdump(tcpdump_pipe)
        self.kill_remote_uiautomator()
        self.kill_remote_monkey()

    def clean_device(self, tcpdump_pipe=None):
        self.clean_capture_process(tcpdump_pipe)
        # TODO Pull not pulled pcap files
        self.clean_capture_dirs()
        self.clean_bin_dirs()
