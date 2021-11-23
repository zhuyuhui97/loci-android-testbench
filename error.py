class CmdError(Exception):
    def __init__(self, cmd=None, ret=None, stdout=None, stderr=None, info=None):
        self.cmd = cmd
        self.stdout = stdout
        self.info = info
        self.ret = ret
        self.stderr = stderr

    def __str__(self):
        result = (  'info:{0}\n'
                    'ret:{1}\n'
                    'stdout:{2}\n'
                    'stderr:{3}\n'
                 ).format(
                    self.info,
                    self.ret,
                    self.stdout,
                    self.stderr
                 )
        return result


class CmdListDeviceError(CmdError):
    pass


class AdbError(CmdError):
    def __init__(self, device, **kwargs):
        self.device = device
        super().__init__(**kwargs)


class RootPrivError(AdbError):
    pass

class AdbFileTransferError(AdbError):
    def __init__(self, src, dst, **kwargs):
        super().__init__(**kwargs)
        self.src = src
        self.dst = dst
    def __str__(self):
        return self.src + ' -> ' + self.dst


# 'adb push' command returned a non-0 value
class AdbPushError(AdbFileTransferError):
    def __str__(self):
        return '[Host] ' + super().__str__() + ' [Device]'


# 'adb pull' command returned a non-0 value
class AdbPullError(AdbFileTransferError):
    def __str__(self):
        return '[Device] ' + super().__str__() + ' [Host]'


class DeviceInitError(AdbError):
    def __init__(self, src=None, dst=None, **kwargs):
        super().__init__(**kwargs)
        self.src = src
        self.dst = dst

    def __str__(self):
        return self.info


# failed to push executable files
class DevicePushExecutableError(DeviceInitError):
    pass


# failed to push 'tcpdump'
class DevicePushTcpdumpError(DevicePushExecutableError):
    pass


# failed to push 'uaplugin.jar' or install 'uaplugin.apk'
class DevicePushUiautomatorError(DevicePushExecutableError):
    pass


# failed to setup executable files
class DeviceSetupExecutableError(DeviceInitError):
    pass


# failed to setup tcpdump
class DeviceSetupTcpdumpError(DeviceSetupExecutableError):
    pass


class DeviceSetupUiautomatorError(DeviceSetupExecutableError):
    pass


class DeviceRunTcpdumpError(AdbError):
    pass


class DeviceRunUiautomatorError(AdbError):
    pass


class DeviceRunMonkeyError(AdbError):
    pass


class DeviceGetPropError(AdbError):
    pass


class DeviceGetCpuArchError(DeviceGetPropError):
    pass


class DeviceGetNetIfError(DeviceGetPropError):
    pass


class DeviceGetBuildPropError(DeviceGetPropError):
    def __str__(self):
        prop = self.device.build_prop
        prop_fails = list()
        for item in prop:
            if prop[item] == 'NULL':
                prop_fails.append(item)
        return str(prop_fails)


class DeviceNetIfDown(DeviceGetNetIfError):
    pass


class DeviceApkError(AdbError):
    def __init__(self, apk_info=None, **kwargs):
        self.apk_info = apk_info
        super().__init__(**kwargs)
    
    def __str__(self):
        fmt = '\'{0}\' @ \'{1}\':({2})>{3}.'
        report = fmt.format(
            self.apk_info, 
            self.device.device_name, 
            self.ret,
            self.stdout
            ) 
        return report


class DeviceApkInstallError(DeviceApkError):
    def __init__(self, errtype=None, apk_path=None, **kwargs):
        super().__init__(**kwargs)
        self.errtype = errtype
        if apk_path != None:
            self.apk_path = apk_path
        else:
            self.apk_path = self.apk_info['apk_path']

    def __str__(self):
        fmt = '\'{0}\' @ \'{1}\':{2}.'
        report = fmt.format(
            self.apk_path, 
            self.device.device_name, 
            self.info
            ) 
        return report


class DeviceApkLaunchError(DeviceApkError):
    pass


class DeviceApkRuntimeError(DeviceApkError):
    pass


class DeviceApkUninstallError(DeviceApkError):
    def __init__(self, errtype=None, pkg_name=None, **kwargs):
        super().__init__(**kwargs)
        self.errtype = errtype
        if pkg_name != None:
            self.pkg_name = pkg_name
        else:
            self.pkg_name = self.apk_info['pkg_name']

    def __str__(self):
        fmt = '\'{0}\' @ \'{1}\':{2}.'
        report = fmt.format(
            self.pkg_name, 
            self.device.device_name, 
            self.info
            ) 
        return report

class DeviceApkBatchError(AdbError):
    def __init__(self, status_list, **kwargs):
        self.status_list = status_list
        super().__init__(**kwargs)
    
    def __str__(self):
        return str(self.status_list)

class DeviceApkBatchInstallError(DeviceApkBatchError):
    pass

class DeviceApkBatchUninstallError(DeviceApkBatchError):
    pass

class DeviceApkBatchUninstallFailHandleError(DeviceApkBatchUninstallError):
    '''批量卸载失败，尝试使用特殊手段处理后仍未被卸载。'''
    def __str__(self):
        pkg_list = list()
        for item in self.status_list:
            pkg_list.append(item['pkg_name'])
        return str(pkg_list)



class DeviceFileNotExist(AdbError):
    def __init__(self, path, **kwargs):
        super().__init__(**kwargs)
        self.path = path


class DevicePcapNotExist(DeviceFileNotExist):
    pass


class ApkPkgError(Exception):
    def __init__(self, path, info=None):
        self.path = path
        self.info = info


class ApkPkgParseError(ApkPkgError):
    pass

class ApkPkgEssentialPropMissing(ApkPkgError):
    pass

class TestbenchInterruptedError(Exception):
    pass

class CommandTimeout(Exception):
    pass