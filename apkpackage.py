import re

from error import *
from utils import *

# TODO add changable permissions here.
CHANGABLE_PERMISSION_LIST = ['', '']

class ApkPackage(dict):

    def __init__(self, path, config):
        self.path = path
        self.config = config
        self.output = ''
        self.read_info()
        # self.check_intergrity()

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

    def get_prop_array_essential(self,regex):
        result = self.get_prop_array_non_essential(regex)
        if len(result) == 0:
            raise ApkPkgEssentialPropMissing(self.path, info=regex)
        return result

    def get_prop_essential(self, regex):
        return self.get_prop_array_essential(regex)[0]

    def get_prop_array_non_essential(self, regex):
        return re.findall(regex, self.output, flags=re.MULTILINE)

    def get_prop_non_essential(self, regex):
        result = self.get_prop_array_non_essential(regex)
        if len(result) == 0:
            return None
        else:
            return result[0]

    def read_info(self):
        ret, self.output, stderr = run_cmdline('aapt dump badging %s' % self.path)
        if ret != 0:
            raise ApkPkgParseError(self.path)
            # BUG Command 'aapt(version=28.0.3, platform=darwin)' crashes on Alipay(versionCode='137' versionName='10.1.55.6000').
            # Not give up when it returned a non-0 value?
        self['apk_path'] = self.path
        self['md5'] = get_md5_from_path(self.path)
        self['app_label'] = self.get_prop_non_essential(r'application-label:\'(.+?)\'$')
        self['pkg_name'] = self.get_prop_essential(r'package: name=\'(.+?)\'\s')
        self['pkg_vercode'] = self.get_prop_non_essential(r'versionCode=\'(.+?)\'\s')
        self['pkg_sdkver'] = self.get_prop_non_essential(r'^sdkVersion:\'(.+)+\'$' )
        tmp = self.get_prop_array_non_essential(r'^targetSdkVersion:\'(.+)+\'$')
        if len(tmp) != 0:  # Such keyword may be invalid for old sdk
            self['pkg_target_sdkver'] = tmp[0]
        else:
            self['pkg_target_sdkver'] = -1
        self['pkg_permission'] = self.get_prop_array_non_essential(r'^uses-permission: name=\'(.+?)\'$')
        self['app_entries'] = self.get_prop_array_essential(r'^launchable-activity: name=\'(.+?)\'\s')
        self['apk_path_parents'] = os.path.split(
            self.path)[0].replace(self.config['input_dir'], '')

    def check_intergrity(self):
        if self['pkg_name'] == None:
            raise ApkPkgEssentialPropMissing(self['apk_path'])
