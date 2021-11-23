import string
import time
import pymysql
import shutil
import os
from utils import *


class ResultWriter(object):
    # TODO Different flags for monkey/uiautomator/manual
    FLAG_AVD_OK = 1
    FLAG_MONKEY_OK = 2
    FLAG_MANUAL_OK = 3
    FLAG_UIAUTOMATOR_OK = 4
    FLAG_BROKEN = 0
    FLAG_INSTALL_FAIL = 5
    FLAG_CRASH = 6
    FLAG_LAUNCH_FAIL = 7

    def __init__(self, config, lock):
        self.config = config
        self.lock = lock
        self.logger = logging.getLogger(name=__name__)
    
    def generate_pcap_name(self, device, apk):
        #apk_file = app_info['apk_path']
        filename = get_filename_from_path(apk['apk_path'])
        #apk_path = self.global_config.CFG_APK_INPUT_PATH
        #apk_file = apk_file.replace(apk_path, '')
        date=str(time.time()).split('.')[0]
        pcap_name = filename.replace('.apk', '')
        pcap_name=pcap_name.split('_')[-1]
        pcap_name = pcap_name + '_' + date + '.pcap'
        return pcap_name

    def register_device_impl(self, device):
        raise NotImplementedError

    def register_device(self, device):
        self.lock.acquire()
        try:
            self.register_device_impl(device)
        except Exception as ex:
            self.lock.release()
            raise ex
        self.lock.release()

    def report_success_impl(self, device, apk, pcap_path, str_flag):
        raise NotImplementedError

    def report_success(self, device, apk, pcap_path, str_flag):
        self.lock.acquire()
        try:
            self.report_success_impl(device, apk, pcap_path, str_flag)
        except Exception as ex:
            self.lock.release()
            raise ex
        self.lock.release()
    
    def report_fail_impl(self, device, apk, str_flag):
        raise NotImplementedError

    def report_fail(self, device, apk, str_flag):
        self.lock.acquire()
        try:
            self.report_fail_impl(device, apk, str_flag)
        except Exception as ex:
            self.lock.release()
            raise ex
        self.lock.release()


class TextResultWriter(ResultWriter):
    pass
    

class SqlTextResultWriter(ResultWriter):

    SQLTEMPLATE_UPDATE_COLLECT_COUNT = (
        'update apk '
        'set collect_count = collect_count+1 '
        'where '
            'hash=\'$hash\'; '
    )

    SQLTEMPLATE_SET_PKG_BROKEN = (
        'update apk '
        'set broken = 1 '
        'where '
            'hash=\'$hash\'; '
    )
    # TODO: disk_id, trigger_method_id需要扩充。前者暂时恒定为0, 后者使用config.json提供的数值。
    SQLTEMPLATE_INSERT_PCAP = (
        'insert into pcap(apk_id, path, collect_device_id, trigger_method_id, disk_id) '
        'values('
            '(select id from apk where hash=\'$hash\'), '
            '\'$path\', '
            '(select id from devices where product_name=\'$product_name\' and sdk_version=\'$sdk_ver\' and adb_id=\'$adb_id\'), '
            '\'$trigger_method\', '
            '1'
        ');\n'
    )

    SQLTEMPLATE_QUERY_DEVICE = (
        'select id '
        'from devices '
        'where '
            'product_name = \'$product_name\' '
        'and '
            'sdk_version = \'$sdk_ver\' '
        'and '
            'adb_id = \'$adb_id\';'
    )

    SQLTEMPLATE_INSERT_DEVICE = (
        'insert into devices(product_name, sdk_version, adb_id) '
        'values(\'$product_name\', $sdk_ver, \'$adb_id\');'
    )

    SQLTEMPLATE_INSERT_INVALID_APK = (
        'insert into invalid_apk(apk_id, device_id) '
        'values('
            '(select id from apk where hash=\'$hash\'), '
            '(select id from devices where product_name=\'$product_name\' and sdk_version=\'$sdk_ver\' and adb_id=\'$adb_id\') '
        ');'
    )

    def __init__(self, config, ofile, lock):
        super().__init__(config, lock)
        self.ofile = ofile

    def register_device_impl(self, device):
        pass

    def sqlcmd_report_success(self, device, apk, pcap_path, str_flag):
        sql_command = list()
        md5 = apk['md5']
        path = pcap_path
        trigger_method = apk['traverse_tag']
        #sql_format = 'update apk set collected_flag=$new_flag where md5=\'$md5\';\n'
        sql_format = self.SQLTEMPLATE_UPDATE_COLLECT_COUNT
        sql_template = string.Template(sql_format)
        sql_command.append(sql_template.safe_substitute(hash=md5))
        #sql_format = 'insert into pcap(apk_id, path, device, trigger_method, date) values((select id from apk where md5=\'$md5\'), \'$path\', \'$device\', \'$trigger_method\', \'$date\');\n'
        sql_format = self.SQLTEMPLATE_INSERT_PCAP
        sql_template = string.Template(sql_format)
        sql_command.append(
            sql_template.safe_substitute(
                hash=md5, 
                path=path, 
                product_name=device.build_prop['product'], 
                sdk_ver=device.build_prop['sdkver'],
                adb_id=device.device_name,
                trigger_method=trigger_method
            )
        )
        return sql_command

    def report_success_impl(self, device, apk, pcap_path, str_flag):
        sql_command = self.sqlcmd_report_success(device, apk, pcap_path, str_flag)
        for item in sql_command:
            self.ofile.write(item)
        os.remove(apk['apk_path'])

    def sqlcmd_report_fail(self, device, apk, str_flag):
        md5 = apk['md5']
        sql_command = list()
        if str_flag == self.FLAG_BROKEN:
            sql_format = self.SQLTEMPLATE_SET_PKG_BROKEN
            sql_template = string.Template(sql_format)
            sql_command.append(sql_template.safe_substitute(hash=md5))
        else: # launch_fail, crash, install_fail
            sql_format = self.SQLTEMPLATE_INSERT_INVALID_APK
            sql_template = string.Template(sql_format)
            sql_command.append(sql_template.safe_substitute(hash=md5, product_name=device.build_prop['product'], sdk_ver=device.build_prop['sdkver'], adb_id=device.device_name))
        return sql_command

    def report_fail_impl(self, device, apk, str_flag):
        sql_command = self.sqlcmd_report_fail(device, apk, str_flag)
        for item in sql_command:
            self.ofile.write(item)
        os.remove(apk['apk_path'])


class DbResultWriter(SqlTextResultWriter):
    def __init__(self, config, dbconn, lock):
        super().__init__(config, None, lock)
        self.dbconn = dbconn
        self.cursor = dbconn.cursor(cursor=pymysql.cursors.DictCursor)

    def move_to_storage(self, device, apk, pcap_path):
        # 访问配置文件：self.config
        # ⬇️改这里！⬇️
        # 已经加了锁，单个进程内同时只能有一个线程执行本操作。
        # 在单进程运行的情况下不必再考虑多生产者造成的计数不准问题。

        store_dir = self.config['stor_dir']
        if not os.path.exists(store_dir):
            os.makedirs(store_dir)

        store_sub_dir = os.listdir(store_dir)  # 读取存放路径中的文件夹
        ########################################################
        # 筛选出数字文件夹
        number_dirs = []
        for dir in store_sub_dir:
            try:
                number_dir = int(dir)  # 如果能够执行，则是数字文件夹，否则为其他文件夹
                number_dirs.append(number_dir)
            except Exception as e:
                #print("发现非数字文件夹：{}".format(dir))
                continue
        ####################################################

        # 如果存储路径下没有任何文件夹，则创建初始化的文件夹1
        dest_dir = os.path.join(store_dir, "1")
        if not len(number_dirs) and os:
            os.makedirs(dest_dir)
            number_dirs.append("1")

        max_index_sub_dir_name = str(max(number_dirs))  # 找到最大下标文件夹
        print(max_index_sub_dir_name)
        if len(os.listdir(os.path.join(store_dir, max_index_sub_dir_name))) < 5000:  # 判断该文件夹的文件数量
            # 将采集的pcap存储进去
            dist_path = os.path.join(store_dir, max_index_sub_dir_name)  # 存放路径
        else:
            # 根据当前最大下标子目录，创建新的目录
            max_index = int(max_index_sub_dir_name) + 1
            # 更新最大下标文件夹
            create_new_max_index_dir = str(max_index)
            new_dir_path = os.path.join(store_dir, create_new_max_index_dir)  # 新建的文件夹
            os.makedirs(new_dir_path)
            dist_path = os.path.join(store_dir, new_dir_path)  # 存放路径

        src_path = os.path.join(self.config['output_dir'], pcap_path)
        #relfilename=str(pcap_path).split("/")[-1]
        new_path = os.path.join(dist_path, pcap_path)
        # 将新的相对路径返回给上层函数。
        if not os.path.exists(src_path):
            return None
        print(src_path + '->' + new_path)
        shutil.move(src_path,new_path)
        new_pcap_path="/PCAP_v2/"+os.path.relpath(new_path,store_dir)

        return new_pcap_path

    def register_device_impl(self, device):
        sql_template = string.Template(self.SQLTEMPLATE_QUERY_DEVICE)
        sql_command = sql_template.safe_substitute(product_name=device.build_prop['product'], sdk_ver=device.build_prop['sdkver'], adb_id=device.device_name)
        if self.cursor.execute(sql_command) == 0:
            sql_template = string.Template(self.SQLTEMPLATE_INSERT_DEVICE)
            sql_command = sql_template.safe_substitute(product_name=device.build_prop['product'], sdk_ver=device.build_prop['sdkver'], adb_id=device.device_name)
            self.cursor.execute(sql_command)
        self.dbconn.commit()

    def report_success_impl(self, device, apk, pcap_path, str_flag):
        new_pcap_path = self.move_to_storage(device, apk, pcap_path)
        if new_pcap_path == None:
            return None
        sql_command = self.sqlcmd_report_success(device, apk, new_pcap_path, str_flag)
        for item in sql_command:
            self.logger.debug(item)
            self.cursor.execute(item)
        self.dbconn.commit()
        os.remove(apk['apk_path'])
    
    def report_fail_impl(self, device, apk, str_flag):
        sql_command = self.sqlcmd_report_fail(device, apk, str_flag)
        for item in sql_command:
            self.logger.debug(item)
            self.cursor.execute(item)
        self.dbconn.commit()
        os.remove(apk['apk_path'])
