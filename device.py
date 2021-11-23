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
    DEFAULT_TIMEOUT_REBOOT = 500
    DEFAULT_TIMEOUT_INSTALL = 180
    DEFAULT_TIMEOUT_UNINSTALL = 180
    DEFAULT_TIMEOUT_CMD = 60

    def __init__(self, device_name, config, thread=None):
        self.logger = logging.getLogger('device.%s' % device_name)
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

    def adb_command(self, command='', params='', run_async=False, **kwargs):
        cmdline_complete = "adb -s {0} {1} {2}".format(self.device_name, command, params)
        return run_cmdline(cmdline_complete, run_async, **kwargs)
    
    def adb_wait_for_device(self, timeout=DEFAULT_TIMEOUT_REBOOT):
        self.adb_command('wait-for-device', timeout=timeout)

    def adb_reboot(self, timeout=DEFAULT_TIMEOUT_CMD):
        self.adb_command('reboot', timeout=timeout)

    def reboot_and_wait(self, timeout=DEFAULT_TIMEOUT_REBOOT):
        self.adb_reboot()
        self.adb_wait_for_boot_complete(timeout=timeout)
        self.run_thread.wait_event.wait(timeout=10)

    def adb_run_remote_cmdline(self, cmd, run_async=False, **kwargs):
        return self.adb_command('shell', '\"{0}\"'.format(cmd), run_async, **kwargs)

    def adb_run_remote_su_cmdline(self, cmd, run_async=False, **kwargs):
        if self.cmd_su_prefix != '':
            cmd = '{0} \'{1}\''.format(self.cmd_su_prefix, cmd)
        return self.adb_run_remote_cmdline(cmd, run_async, **kwargs)

    def adb_push(self, src_path, dst_path):
        # TODO Handle failure when it returned an non-0 value: ['error: no devices found']
        ret, stdout, stderr = self.adb_command('push', '\'{0}\' \'{1}\''.format(src_path, dst_path))
        if ret != 0:
            raise AdbPushError(device=self, src=src_path, dst=dst_path, ret=ret, stdout=stdout, stderr=stderr)

    def adb_pull(self, src_path, dst_path):
        ret, stdout, stderr = self.adb_command('pull', '\'{0}\' \'{1}\''.format(src_path, dst_path))
        if ret != 0:
            raise AdbPullError(device=self, src=src_path, dst=dst_path, ret=ret, stdout=stdout, stderr=stderr)

    def adb_wait_for_boot_complete(self, timeout=DEFAULT_TIMEOUT_REBOOT):
        self.logger.debug('Waiting for device online...')
        self.adb_wait_for_device(timeout=timeout)
        self.logger.debug('Waiting for device boot completed...')
        ret, output, stderr = self.adb_run_remote_cmdline('while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done; input keyevent 82', timeout=self.DEFAULT_TIMEOUT_CMD)
        self.logger.debug('Boot completed.')

    def list_3rdparty_apps(self):
        ret, output, stderr = self.adb_run_remote_cmdline("pm list packages -3")
        lines = output.split('\n')
        result = []
        for item in lines:
            if item.strip() == '':
                continue
            pkg_name = re.findall(r'^package:(.*)$', item)[0]
            if pkg_name not in self.global_config['env_pkgs']:
                result.append(pkg_name)
        return result

    def pull_traffic(self, src_path, dest_path):
        ret, output, stderr = self.adb_run_remote_cmdline("ls %s" % src_path)
        if ret != 0:
            raise AdbError(device=self, ret=ret, stdout=output, stderr=stderr, info='Failed to list \'{0}\'.'.format(src_path))
        res = output.split()
        for item in res:
            item = item.strip()
            item = src_path + '/' + item
            self.adb_pull(item, dest_path)
        ret, output, stderr = self.adb_run_remote_cmdline("rm -rf \'%s/*\'" % src_path)

    def install_apk_local(self, apk_info=None, apk_path=None, install_timeout=DEFAULT_TIMEOUT_INSTALL):
        '''将位于上位机上的APK软件包安装到手机上。

        Args:
            apk_info: foo
            apk_path: bar
        

        '''
        device_name = self.device_name
        if apk_info != None:
            app_label = apk_info['app_label']
            apk_path = apk_info['apk_path']
        elif apk_path != None:
            app_label = '(dummy){0}'.format(apk_path)
        else:
            raise DeviceApkInstallError(device=self, info='APK file Not specified.')
        # -l: forward lock application
        # -r: replace existing application
        # -t: allow test packages
        # -s: install application on sdcard
        # -d: allow version code downgrade
        # -g: grant all runtime permissions
        ret, output, stderr = self.adb_command('install -r -t -d -g', apk_path, timeout=install_timeout)
        if ret != 0:
            raise DeviceApkInstallError(
                device=self, apk_info=apk_info, apk_path = apk_path, ret=ret, stdout=output, stderr=stderr, info='Unknown failure')
        output_lines = output.split('\n')
        if 'Success' in output_lines[-1]:
            return
        elif 'Failure' in output_lines[-1]:
            regex = r"Failure \[(.*?): (.*?)\]"
            pattern = re.compile(regex)
            match = pattern.match(output_lines[-1])
            raise DeviceApkInstallError(device=self, errtype=match.group(1), apk_info=apk_info, apk_path=apk_path, cmd='adb_install', ret=ret, stdout=output, stderr=stderr, info=match.group(2))
        else: # TODO: 
            raise DeviceApkInstallError(device=self, errtype='OTHER', apk_info=apk_info, apk_path=apk_path, cmd='adb_install', ret=ret, stdout=output, stderr=stderr, info='Unknown failure')
        # All runtime permissions are granted at installtion. 
        # if (int(apk_info['pkg_target_sdkver']) >= 23) and (apk_info['pkg_target_sdkver'] != -1):
        #     apk_info.grant_permissions(self)

    def launch_app(self, apk_info):
        # TODO Only launch first entry???
        pkg_name = apk_info['pkg_name']
        if len(apk_info['app_entries']) == 0:
            return
        app_entry = apk_info['app_entries'][0]
        cmd = "am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -n %s/%s" % (
            pkg_name, app_entry)
        ret, output, stderr = self.adb_run_remote_cmdline(cmd)
        if ret != 0:
            raise DeviceApkLaunchError(
                device=self, cmd=cmd, apk_info=apk_info, ret=ret, stdout=output, stderr=stderr)

    def uninstall_apk_local_batch(self, apk_info_list=None, pkg_name_list=None, uninstall_timeout=DEFAULT_TIMEOUT_UNINSTALL):
        fail = False
        err_list = dict()
        if apk_info_list != None:
            pkg_name_list = list()
            for item in apk_info_list:
                pkg_name_list.append(item['pkg_name'])
        for item in pkg_name_list:
            try:
                self.uninstall_apk_local(pkg_name=item, uninstall_timeout=uninstall_timeout)
            except DeviceApkUninstallError as ex:
                fail = True
                if ex.errtype not in err_list:
                    err_list[ex.errtype] = list()
                err_obj = dict()
                err_obj['pkg_name'] = item
                err_obj['errtype'] = ex.errtype
                err_obj['ex'] = ex
                err_list[ex.errtype].append(err_obj)
        if fail:
            raise DeviceApkBatchUninstallError(device=self, status_list=err_list)

    def uninstall_apk_local(self, apk_info=None, pkg_name=None, uninstall_timeout=DEFAULT_TIMEOUT_UNINSTALL):
        device_name = self.device_name
        if apk_info != None:
            pkg_name = apk_info['pkg_name']
        ret, output, stderr = self.adb_command('uninstall', pkg_name, timeout=uninstall_timeout)
        if ret != 0:
            raise DeviceApkUninstallError(
                device=self, apk_info=apk_info, pkg_name=pkg_name, ret=ret, stdout=output, stderr=stderr, info='Unknown failure')
        output_lines = output.split('\n')
        if 'Success' in output_lines[-1]:
            return
        elif 'Failure' in output_lines[-1]:
            regex = r"Failure \[(.+)\]"
            pattern = re.compile(regex)
            match = pattern.match(output_lines[-1])
            raise DeviceApkUninstallError(device=self, errtype=match.group(1), apk_info=apk_info, pkg_name=pkg_name, cmd='adb_uninstall', ret=ret, stdout=output, stderr=stderr, info=match.group(1))
        else: # TODO:
            raise DeviceApkUninstallError(device=self, errtype='OTHER', apk_info=apk_info, pkg_name=pkg_name, cmd='adb_uninstall', ret=ret, stdout=output, stderr=stderr, info='Unknown failure')

    def handle_uninstall_failure_batch(self, err_list, reboot_timeout=DEFAULT_TIMEOUT_REBOOT):
        reboot_request = False
        if len(err_list) == 0:
            return
        for key in err_list:
            if key == 'DELETE_FAILED_DEVICE_POLICY_MANAGER':
                reboot_request = True
                for item in err_list[key]:
                    self.purge_apk(item['pkg_name'], reboot=False)
            else:
                reboot_request = True
                for item in err_list[key]:
                    self.purge_apk(item['pkg_name'], reboot=False)
        if reboot_request:
            self.reboot_and_wait(timeout=reboot_timeout)
            


    def handle_uninstall_failure(self, pkg_name, errtype, ex, reboot_timeout=DEFAULT_TIMEOUT_REBOOT):
        err_item = {'pkg_name': pkg_name, 'errtype': errtype, 'ex':ex}
        err_list = {errtype: [err_item]}
        self.handle_uninstall_failure_batch(err_list, reboot_timeout=reboot_timeout)

    def purge_apk_files(self, pkg_name):
        data_dir = '/data/data/{0}'.format(pkg_name)
        ret, output, stderr = self.adb_run_remote_cmdline('pm path {0}'.format(pkg_name))
        apk_inst_dirname = re.findall("/data/app/(.+?)/", output)[0]
        apk_dir = '/data/app/{0}'.format(apk_inst_dirname)
        self.adb_run_remote_su_cmdline('rm -rf {0}'.format(apk_dir))
        self.adb_run_remote_su_cmdline('rm -rf {0}'.format(data_dir))

    def purge_apk(self, pkg_name, reboot=True, reboot_timeout=DEFAULT_TIMEOUT_REBOOT):
        self.purge_apk_files(pkg_name)
        if reboot:
            self.reboot_and_wait(timeout=reboot_timeout)

    def clean_3rdparty_apps(self, uninstall_timeout=DEFAULT_TIMEOUT_UNINSTALL, reboot_timeout=DEFAULT_TIMEOUT_REBOOT):
        self.logger.debug('Detecting 3rd party apps on device.')
        apps = self.list_3rdparty_apps()
        if len(apps) == 0:
            self.logger.debug('Device is clean.')
            return
        self.logger.debug('Detected {0} 3rd party apps.'.format(len(apps)))
        try:
            self.uninstall_apk_local_batch(pkg_name_list=apps, uninstall_timeout=uninstall_timeout)
        except DeviceApkBatchUninstallError as ex:
            self.logger.debug('Failed to uninstall some 3rd party apps.')
            self.handle_uninstall_failure_batch(ex.status_list, reboot_timeout=reboot_timeout)
        apps = self.list_3rdparty_apps()
        if len(apps) != 0:
            err_list = list()
            for item in apps:
                err_list.append({'pkg_name': item, 'errtype': 'UNINSTALL_FAILURE_HANDLE_FAILED', 'ex': None})
            raise DeviceApkBatchUninstallFailHandleError(device=self, status_list=err_list)

    @classmethod
    def __list_device_all(cls):  # Show all android device connected to the PC.
        cmd = 'adb devices'
        ret, output, stderr = run_cmdline(cmd)
        if ret != 0:
            raise CmdListDeviceError(
                cmd=cmd, ret=ret, stdout=output, stderr=stderr)
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
        '''获取手机的SoC架构'''
        cmd = 'uname -m'
        ret, output, stderr = self.adb_run_remote_cmdline(cmd)
        if ret != 0:
            raise DeviceGetCpuArchError(device=self, cmd=cmd, ret=ret, stdout=output, stderr=stderr)
        return output

    def get_device_netif(self):
        cmd = 'dumpsys netstats'
        ret, output, stderr = self.adb_run_remote_cmdline(cmd)
        lines = output.split('\n')
        netif = None
        for i in range(len(lines)):
            if lines[i].strip() == 'Active interfaces:':
                netif = re.findall(r'iface=(.+?)\s', lines[i+1])
                break
        if (ret != 0) or (len(netif) == 0):
            raise DeviceGetNetIfError(device=self, cmd=cmd, ret=ret, stdout=output, stderr=stderr)
        return netif[0]

    def get_device_buildprop(self):
        '''从build.prop中读取必要的系统信息'''
        flag = True
        cmd = 'getprop ro.product.brand'
        self.build_prop['brand'] = 'NULL'
        ret, output, stderr = self.adb_run_remote_cmdline(cmd)
        if output != '':
            self.build_prop['brand'] = output
        else:
            flag = False
        cmd = 'getprop ro.build.product'
        self.build_prop['product'] = 'NULL'
        ret, output, stderr = self.adb_run_remote_cmdline(cmd)
        if output != '':
            self.build_prop['product'] = output
        else:
            flag = False
        cmd = 'getprop ro.build.version.sdk'
        self.build_prop['sdkver'] = 'NULL'
        ret, output, stderr = self.adb_run_remote_cmdline(cmd)
        if output != '':
            self.build_prop['sdkver'] = output
        else:
            flag = False
        cmd = 'getprop ro.build.tags'
        self.build_prop['build_tags'] = 'NULL'
        ret, output, stderr = self.adb_run_remote_cmdline(cmd)
        if output != '':
            self.build_prop['build_tags'] = output
        else:
            flag = False
        self.device_tag = '{}/{}/{}'.format(self.build_prop['brand'],
                                            self.build_prop['product'], self.build_prop['sdkver'])
        if not flag:
            raise DeviceGetBuildPropError(self)

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
        try:
            self.adb_push(local_bin, dst_bin)
        except AdbPushError as ex:
            raise DevicePushTcpdumpError( 
                device=self, src=local_bin, dst=dst_bin, ret=ex.ret, stdout=ex.stdout, stderr=ex.stderr)
        cmd = 'mkdir {0}'.format(remote_bin_dir)
        ret, output, stderr = self.adb_run_remote_su_cmdline(cmd)
        cmd = 'cp {0}/tcpdump {1}/tcpdump'.format(remote_cap_dir, remote_bin_dir)
        ret, output, stderr = self.adb_run_remote_su_cmdline(cmd)
        if ret != 0:
            raise DeviceSetupTcpdumpError(
                device=self, cmd=cmd, ret=ret, stdout=output, stderr=stderr, info='Failed to copy tcpdump binary')
        cmd = 'rm {0}/tcpdump'.format(remote_cap_dir)
        self.adb_run_remote_cmdline(cmd)
        cmd = 'chmod +x {}/tcpdump'.format(remote_bin_dir)
        ret, output, stderr = self.adb_run_remote_su_cmdline(cmd)
        if ret != 0:
            raise DeviceSetupTcpdumpError(
                device=self, cmd=cmd, ret=ret, stdout=output, stderr=stderr, info='Failed to `chmod+x` tcpdump binary')

    def check_tcpdump(self):
        remote_bin_dir = self.global_config['remote_bin_dir']
        # TODO use remote_bin_path?
        cmd = '{0}/tcpdump --version'.format(remote_bin_dir)
        ret, output, stderr = self.adb_run_remote_su_cmdline(cmd)
        if ret != 0:
            raise DeviceSetupTcpdumpError(
                device=self, cmd=cmd, ret=ret, stdout=output, stderr=stderr, info='Executable tcpdump is not configured properly.')

    def setup_tcpdump(self, local_bin_path, remote_bin_path):
        # TODO We assume all devices are ARM-based currently.
        # TODO Read executable file name from config.ini
        self.push_tcpdump()
        self.check_tcpdump()

    def start_tcpdump_pipe(self, netif, capture_file_path):
        remote_bin_dir = self.global_config['remote_bin_dir']
        #cmdline = ('adb -s {0} shell {4} {1}/tcpdump -i {2} -w {3}'.format(self.device_name, remote_bin_dir, netif, capture_file_path, self.cmd_su_prefix))
        cmdline = ('{0}/tcpdump -i {1} -w {2}'.format(remote_bin_dir, netif, capture_file_path))
        pipe = self.adb_run_remote_su_cmdline(cmdline, run_async=True)
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

    def push_uiautomator(self):
        config = self.global_config
        local_bin_dir = config['local_bin_dir']
        bin_uaplugin = config['bin_uaplugin']
        remote_cap_dir = config['remote_cap_dir']
        remote_bin_dir = config['remote_bin_dir']
        dummymain_path = os.path.join(config['current_dir'], local_bin_dir, 'uaplugin_dummymain.apk')
        uaplugin_path = os.path.join(config['current_dir'], local_bin_dir, 'uaplugin_test.apk')
        try:
            self.install_apk_local(apk_path=dummymain_path)
        except DeviceApkInstallError as ex:
            raise DeviceSetupUiautomatorError(
                device=self, cmd=ex.cmd, ret=ex.ret, stdout=ex.stdout, stderr=ex.stderr, info='Failed to install uiautomator dummymain package.')
        try:
            self.install_apk_local(apk_path=uaplugin_path)
        except DeviceApkInstallError as ex:
            raise DeviceSetupUiautomatorError(
                device=self, cmd=ex.cmd, ret=ex.ret, stdout=ex.stdout, stderr=ex.stderr, info='Failed to install uiautomator test package.')


    def launch_uiautomator(self):
        cmd = 'am instrument -w -r -e debug false cn.edu.ujn.loci.uaplugin2.test/androidx.test.runner.AndroidJUnitRunner'
        self.uiauto_pipe = self.adb_run_remote_cmdline(cmd, run_async=True)
        # TODO test it!

    def kill_remote_uiautomator(self):
        if self.uiauto_pipe != None:
            self.uiauto_pipe.terminate()
            self.uiauto_pipe.poll()

    def launch_monkey(self, pkg_name, op_count):
        #cmd = "\'nohup monkey -p %s --throttle 400 -v-v-v %d >/dev/null 2>&1 &\'" % (pkg_name, op_count)
        cmd = "monkey -p %s --throttle 400 -v-v-v %d" % (pkg_name, op_count)
        ret, output, stderr = self.adb_run_remote_cmdline(cmd)
        if ret != 0:
            raise DeviceRunMonkeyError(
                device=self, cmd=cmd, ret=ret, stdout=output, stderr=stderr)
        return ret
        # TODO test it!

    def kill_remote_monkey(self):
        self.adb_run_remote_su_cmdline('killall com.android.commands.monkey')
        # （:-o）

    def test_file_exists(self, filepath):
        EXIST_FLAG = 'YES'
        cmd = "if [ -e {0} ]; then echo {1}; fi".format(escape_path(filepath), EXIST_FLAG)
        ret, output, stderr = self.adb_run_remote_su_cmdline(cmd)
        if ret != 0:
            raise AdbError(device=self, cmd=cmd, ret=ret, stdout=output, stderr=stderr)
        return (output == EXIST_FLAG)

    def init_capture_dirs(self):
        pass

    ADBROOT_BUILDTAGS = ['test-keys', 'userdebug', 'eng']
    def init_root_priv(self):
        self.adb_command('root')
        ret, output, stderr = self.adb_run_remote_su_cmdline('whoami')
        self.logger.debug("Username without superuser prefix: {0}".format(output))
        if output == 'root':
            return
        self.cmd_su_prefix = 'su -c'
        ret, output, stderr = self.adb_run_remote_su_cmdline('whoami')
        self.logger.debug("Username using superuser prefix: {0}".format(output))
        if output != 'root':
            raise RootPrivError(self)

    def init_device(self):
        self.logger.debug('Getting device properties...')
        try:
            self.get_device_buildprop()
        except DeviceGetBuildPropError as e:
            self.logger.warning('Failed to get some info from build.prop: ' + str(e.info))
        self.arch = self.get_device_cpu_arch()
        self.netif = self.get_device_netif()
        self.logger.debug('Getting root shell...')
        self.init_root_priv()
        # self.logger.debug('Getting root shell')
        # self.init_capture_dirs()
        self.logger.debug('Cleaning 3rd party apps...')
        self.clean_3rdparty_apps()
        self.logger.debug('Killing wild capture process...')
        self.kill_remote_tcpdump(None)
        local_bin_path = os.path.join(self.global_config['current_dir'], self.global_config['local_bin_dir'])
        self.logger.debug('Setting up binaries...')
        self.setup_tcpdump(local_bin_path, None)
        self.push_uiautomator()

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

    # TODO handle uninstall failure
    def clean_uaplugin(self):
        self.adb_run_remote_cmdline('pm uninstall cn.edu.ujn.loci.uaplugin2.test')
        self.adb_run_remote_cmdline('pm uninstall cn.edu.ujn.loci.uaplugin2')

    def clean_device(self, tcpdump_pipe=None):
        self.clean_capture_process(tcpdump_pipe)
        self.clean_capture_dirs()
        self.clean_bin_dirs()
        self.clean_uaplugin()
