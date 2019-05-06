import re

from error import *
from utils import *

# TODO add changable permissions here.
CHANGABLE_PERMISSION_LIST = ['', '']

class ApkPackage(dict):

    def __init__(self, path, config):
        self.path = path
        self.config = config
        self.read_info()
        self.check_intergrity()

    @staticmethod
    def is_changable_permission(permission):
        return permission.startswith('android.permission.')

    def set_run_device(self, device):
        self.device = device

    def grant_permissions(self, device):
        app_label = self['app_label']
        pkg_name = self['pkg_name']
        permissions = self['pkg_permission']
        flag_clear = 0
        for item in permissions:
            if device.run_thread.gev_stop.is_set():
                raise TestbenchInterruptedError
            # This permission is not changable, skip.
            if not ApkPackage.is_changable_permission(item):
                continue
            ret, output = device.adb_run_remote_cmdline("pm grant %s %s" % (pkg_name, item))
            flag_clear = flag_clear ^ ret
            if ret != 0:
                self.device.logger.error('Failed to grant %s for %s: %s' %
                            (item, app_label, output))
        return (flag_clear == 0)

    def read_info(self):
        ret, output = run_cmdline('aapt dump badging %s' % self.path)
        if ret != 0:
            logger.error('errno=%d, %s' % (ret, output))
            ApkPkgParseError(self.path)
            # BUG Command 'aapt(version=28.0.3, platform=darwin)' crashes on Alipay(versionCode='137' versionName='10.1.55.6000').
            # Not give up when it returned a non-0 value?
        self['apk_path'] = self.path
        self['md5'] = get_md5_from_path(self.path)
        self['app_label'] = re.findall(
            r'application-label:\'(.+?)\'$', output, flags=re.MULTILINE)[0]
        self['pkg_name'] = re.findall(
            r'package: name=\'(.+?)\'\s', output, flags=re.MULTILINE)[0]
        self['pkg_vercode'] = re.findall(
            r'versionCode=\'(.+?)\'\s', output, flags=re.MULTILINE)[0]
        self['pkg_sdkver'] = re.findall(
            r'^sdkVersion:\'(.+)+\'$', output, flags=re.MULTILINE)[0]
        tmp = re.findall(r'^targetSdkVersion:\'(.+)+\'$',
                        output, flags=re.MULTILINE)
        if len(tmp) != 0:  # Such keyword may be invalid for old sdk
            self['pkg_target_sdkver'] = tmp[0]
        else:
            self['pkg_target_sdkver'] = -1
        self['pkg_permission'] = re.findall(
            r'^uses-permission: name=\'(.+?)\'$', output, flags=re.MULTILINE)
        self['app_entries'] = re.findall(
            r'^launchable-activity: name=\'(.+?)\'\s', output, flags=re.MULTILINE)
        self['apk_path_parents'] = os.path.split(
            self.path)[0].replace(self.config['input_dir'], '')

    def check_intergrity(self):
        if self['pkg_name'] == None:
            raise ApkPkgParseError(self['apk_path'])
