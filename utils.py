import subprocess
import os
import logging
import re
import shlex

def setup_logger():
    pass

def run_cmdline(cmd, run_async=False, **kwargs):
    # Default arguments for subprocess functions
    if 'shell' not in kwargs:
        kwargs['shell'] = False
    if 'stdin' not in kwargs:
        kwargs['stdin'] = subprocess.DEVNULL
    if 'stdout' not in kwargs:
        kwargs['stdout'] = subprocess.PIPE
    if 'stderr' not in kwargs:
        kwargs['stderr'] = subprocess.PIPE
    if 'bufsize' not in kwargs:
        kwargs['bufsize'] = 1
    logging.getLogger('cmd').debug('%s %s' % ( '(ASYNC)' if run_async else ''  , cmd))
    cmd_array = shlex.split(cmd)
    if run_async:
        return run_cmdline_async(cmd_array, **kwargs)
    else:
        return run_cmdline_sync(cmd_array, **kwargs)

def run_cmdline_sync(cmd_array, **kwargs):
    #result = subprocess.run(cmd_array, shell=False, stdout=subprocess.PIPE)
    result = subprocess.run(cmd_array, **kwargs)
    return result.returncode, result.stdout.decode().strip(), result.stderr.decode().strip()

def run_cmdline_async(cmd_array, **kwargs):
    #return subprocess.Popen(cmd_array, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE, shell=False, bufsize=1)
    return subprocess.Popen(cmd_array, **kwargs)

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
