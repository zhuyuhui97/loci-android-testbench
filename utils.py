import subprocess
import os
import logging
import re
import shlex

logger = logging.getLogger(__name__)


# def run_cmdline(cmd):
#     logger.debug('[CMD]>%s' % cmd)
#     ret, output = subprocess.getstatusoutput(cmd)
#     return ret, output

def run_cmdline(cmd):
    logger.debug('[CMD]>%s' % cmd)
    cmd_array = shlex.split(cmd)
    result = subprocess.run(cmd_array, shell=False, stdout=subprocess.PIPE)
    return result.returncode, result.stdout.decode().strip()

def get_elf_arch(elf_path):
    # run_cmdline('readelf')
    pass


def check_path(path):
    if not os.path.exists(path):
        os.mkdir(path)


def walk_path(path):
    file_list = list()
    for root, dirs, files in os.walk(path):
        for item in files:
            file_list.append(os.path.join(root, item))
    return file_list




def get_filename_from_path(path):
    if not os.path.isfile(path):
        return None
    tmp = os.path.split(path)
    if len(tmp) == 2:
        return tmp[1]
    else:
        return None


def get_md5_from_filename(filename):
    #result = re_get_hex32(filename)
    pattern = '[0-9a-f]{128}|[0-9a-f]{64}|[0-9a-f]{32}|[0-9a-f]{16}|[0-9a-f]{8}'
    result = re.findall(pattern, filename)
    if len(result) == 0:
        return None
    else:
        return result[0]


def re_get_hex32(src_str):
    pattern = '[0-9a-f]{32}'
    hex32 = re.findall(pattern, src_str)
    return hex32

def get_md5_from_path(path):
    filename = get_filename_from_path(path)
    if filename == None:
        return None
    return get_md5_from_filename(filename)


def check_config(config):
    flag = True
    flag &= config['trigger'] in ['1', '2', '3']
    flag &= config['trigger'] in ['1', '2', '3']

def escape_path(path):
    return path.replace(' ', '\\ ')

def get_PATH():
    return os.getenv('PATH').split(':')

def whereis(exec_name):
    PATH = get_PATH()
    result = list()
    for item in PATH:
        search_path = os.path.join(item, exec_name)
        if os.path.exists(search_path):
            result.append(search_path)
    return result


def whereis_adb():
    candidates = whereis('adb')
    # TODO Select best adb version from candidates
    return candidates[0]
