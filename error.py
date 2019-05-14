class CmdError(Exception):
    def __init__(self, cmd, ret=None, output=None, info=None):
        self.cmd = cmd
        self.output = output
        self.info = info
        self.ret = ret


class CmdListDeviceError(CmdError):
    pass


class AdbError(CmdError):
    def __init__(self, device, cmd=None, ret=None, output=None, info=None):
        self.device = device
        super().__init__(cmd, ret, output, info)


class RootPrivError(AdbError):
    pass

class AdbFileTransferError(AdbError):
    def __init__(self, device, src, dst, output=None):
        super().__init__(device, output=output)
        self.src = src
        self.dst = dst


# 'adb push' command returned a non-0 value
class AdbPushError(AdbFileTransferError):
    pass


# 'adb pull' command returned a non-0 value
class AdbPullError(AdbFileTransferError):
    pass


class DeviceInitError(AdbError):
    def __init__(self, device, src=None, dst=None, cmd=None, ret=None, output=None, info=None):
        super().__init__(device, cmd=cmd, ret=ret, output=output, info=info)
        self.src = src
        self.dst = dst

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
    pass


class DeviceNetIfDown(DeviceGetNetIfError):
    pass


class DeviceApkError(AdbError):
    pass


class DeviceApkInstallError(DeviceApkError):
    pass


class DeviceApkLaunchError(DeviceApkError):
    pass


class DeviceApkRuntimeError(DeviceApkError):
    pass


class DeviceApkUninstallError(DeviceApkError):
    pass


class DeviceFileNotExist(AdbError):
    def __init__(self, device, path, info=None):
        super().__init__(device=device, info=info)
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