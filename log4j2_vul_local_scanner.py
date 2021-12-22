#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Log4j2 local scanner  LiJieJie  my[at]lijiejie.com
# works under python2.7 / 2.6 / 3.x, no extra lib required


import os
import time
from datetime import datetime
import zipfile
import re
import shutil
import sys
import subprocess
import platform
import socket
import json
import random

if sys.version_info < (3, 0):  # python2.x
    from cStringIO import StringIO as IO_Lib
    import urllib2 as request_lib
else:  # python3.x
    from io import BytesIO as IO_Lib
    import urllib.request as request_lib

if sys.version_info < (2, 7):
    from subprocess import PIPE, Popen     # python2.6 has no check_output

TMP_DIR = '/tmp/log4j2_scan/'
process_list = []
# each java process, report only once
reported_PIDs = set()
reported_PIDs_jvm = set()
reported_PIDs_sys_env = set()
temp_fixed_PIDs = {}
report_url = ""  # "Api/sync_log4j_report"
self_pid = os.getpid()


def print_msg(msg):
    print("[%s] %s" % (datetime.now().strftime('%H:%M:%S'), msg))


def get_cmd_out(cmd):
    try:
        if sys.version_info < (2, 7):
            proc = Popen(cmd.split(), stdout=PIPE)    # python2.6
            return proc.communicate()[0].strip()
        else:
            out = subprocess.check_output(cmd, shell=True).strip()
            return out
    except Exception as e:
        return ""


def get_pid_owner(pid):
    owner = get_cmd_out('ps -o user= -p %s' % pid)
    return owner.decode() if sys.version_info > (2, 7) else owner


def get_memory_usage():
    try:
        with open('/proc/%s/status' % self_pid) as f:
            for line in f.read().split('\n'):
                if line.startswith('VmRSS:'):
                    memory_usage = line.split(':')[1].strip().lower()
                    used_count, unit = memory_usage.split(' ')
                    unit = unit.strip()
                    used_count = float(used_count)
                    if unit == 'mb':
                        return used_count
                    elif unit == 'kb':
                        return used_count / 1024.0
                    elif unit == 'gb':
                        return used_count * 1024
        return 0
    except Exception as e:
        return 0


def get_all_java_process():
    try:
        items = os.walk('/proc').next()[1]
    except Exception as e:
        items = next(os.walk('/proc'))[1]    # python3.x
    try:
        for pid in items:
            if not pid.isdigit():
                continue
            _path = '/proc/%s/cmdline' % pid
            if not os.path.exists(_path):
                continue
            cmdline = open(_path).read().replace('\0', ' ')
            if cmdline and os.path.basename(cmdline.split()[0]).lower() == 'java':
                jvm_args_enabled = True if cmdline.find('-Dlog4j2.formatMsgNoLookups=true') > 0 else False
                # os env check
                tag = ""
                with open('/proc/%s/environ' % pid) as f:
                    content = f.read().replace('\0', '\n').replace(' ', '')
                    if content.find('LOG4J_FORMAT_MSG_NO_LOOKUPS=true') > 0:
                        sys_env_enabled = True
                    else:
                        sys_env_enabled = False
                        # wrong way to fix
                        if content.find("FORMAT_MSG_NO_LOOKUPS=true") >= 0:
                            tag += "sys_env_misconfiguration,"

                # is docker / k8s process
                docker_image = ""
                with open('/proc/%s/cgroup' % pid) as f:
                    content = f.read()
                    if content.find('docker') >= 0:
                        tag += "docker,"
                        root_path = '/proc/%s/root' % pid
                        docker_image = get_container_image(pid)
                    elif content.find('/kubepods') >= 0:
                        tag += "k8s,"
                        root_path = '/proc/%s/root' % pid
                        docker_image = get_container_image(pid)
                    else:
                        root_path = ''
                process_list.append({"pid": pid,
                                     "user": get_pid_owner(pid),
                                     "cmdline": cmdline,
                                     "jvm_args_enabled": jvm_args_enabled,
                                     "sys_env_enabled": sys_env_enabled,
                                     "root_path": root_path,
                                     "docker_image": docker_image,
                                     "log4j_version": "",
                                     "log4j_jar_path": "",
                                     "tag": tag})
    except Exception as e:
        print_msg('[get_all_java_process.error]: %s' % str(e))
    return process_list


def get_jar_count(process):
    try:
        items = os.walk('/proc/%s/fd/' % process['pid']).next()[2]
    except Exception as e:
        items = next(os.walk('/proc/%s/fd/' % process['pid']))[2]    # python3.x
    try:
        loop_count = 0
        jar_count = 0
        for fd_num in items:
            file_path = '/proc/%s/fd/%s' % (process['pid'], fd_num)
            if os.path.islink(file_path):
                file_path = os.readlink(file_path)
            loop_count += 1
            if loop_count % 1000 == 0:
                time.sleep(0.002)
            if file_path.endswith('.jar'):
                jar_count += 1
        print_msg('PID %s got %s jar files to scan' % (process['pid'], jar_count))
        return jar_count
    except Exception as e:
        print_msg('[get_jar_count.error]: %s' % str(e))


# search for log4j-core*.jar
def scan_jar_file(process):
    try:
        items = os.walk('/proc/%s/fd/' % process['pid']).next()[2]
    except Exception as e:
        items = next(os.walk('/proc/%s/fd/' % process['pid']))[2]    # python3.x
    try:
        for fd_num in items:
            file_path = '/proc/%s/fd/%s' % (process['pid'], fd_num)
            if os.path.islink(file_path):
                file_path = os.readlink(file_path)
            if not file_path.endswith('.jar'):
                continue

            base_name = os.path.basename(file_path)
            if base_name.startswith('log4j-core-'):
                version_check(process, process['root_path'] + file_path, base_name, file_path)
            else:
                scan_a_fat_jar(process, process['root_path'] + file_path, file_path)
            time.sleep(0.01)
    except Exception as e:
        print_msg('[scan_jar_file.error]: %s' % str(e))


# recursively unzip and version check
def scan_a_fat_jar(process, file_path, ancestor, recurse_level=1):
    try:
        # with zipfile.ZipFile(file_path, 'r') as obj_zip:    # python2.6 not work
        obj_zip = zipfile.ZipFile(file_path, 'r')
        for _name in obj_zip.namelist():
            if _name.endswith('org.apache.logging.log4j/log4j-core/pom.properties'):
                content = obj_zip.open(_name).read()
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith('version='):
                        version_string = line[len('version='):].split()[0]
                        version_check(process, '', '', ancestor, pom_version=version_string)

            if not _name.endswith('.jar'):
                continue
            base_name_child = os.path.basename(_name)
            if base_name_child.startswith('log4j-core-'):   # copy to temp dir and check
                source = obj_zip.open(_name)
                temp_file_path = os.path.join(TMP_DIR, base_name_child)
                target = open(temp_file_path, "wb")
                # with source, target:
                #     shutil.copyfileobj(source, target)   # python2.6 not work
                shutil.copyfileobj(source, target)
                source.close()
                target.close()
                version_check(process, temp_file_path, base_name_child, ancestor)
                os.remove(temp_file_path)
            else:
                child_jar_file = obj_zip.open(_name)
                a_child_jar = IO_Lib(child_jar_file.read())
                if get_memory_usage() > 300.0:    # 300 MB at most
                    print_msg('[ERROR] Memory exceeded, further scan stopped')
                    process['tag'] += 'out_of_memory,'
                else:
                    recurse_level += 1
                    if recurse_level < 5:
                        scan_a_fat_jar(process, a_child_jar, ancestor)
        obj_zip.close()
    except Exception as e:
        print_msg('[scan_a_fat_jar.error]: %s' % str(e))


def version_check(process, file_path, base_name, ancestor, pom_version=''):
    try:
        global temp_fixed_PIDs
        if pom_version:
            log4j_version = pom_version
        else:
            log4j_version = base_name[len('log4j-core-'):-4].lower()
        process['log4j_version'] += log4j_version + ","
        process['log4j_jar_path'] += ancestor + ","
        if log4j_version.find('{company}sec') > 0:    # safe version, replace it to your company name
            process['tag'] += '{company}sec,'
            print_msg('[INFO] {company} sec version found.')
            return

        log4j_version = log4j_version.split('-')[0]
        log4j_version = re.sub('[a-zA-Z]', '', log4j_version)    # remove non-number string
        int_version = int(log4j_version.split('.')[0]) * 100 + int(log4j_version.split('.')[1])
        if int_version >= 217 or int_version < 200 or log4j_version == '2.12.2':
            process['tag'] += 'safe,'
            print_msg('A safe version log4j found: %s' % log4j_version)
            return

        if pom_version == '':
            class_found = False
            # with zipfile.ZipFile(file_path, 'r') as obj_zip:
            obj_zip = zipfile.ZipFile(file_path, 'r')
            for _name in obj_zip.namelist():
                if _name == 'org/apache/logging/log4j/core/lookup/JndiLookup.class':
                    class_found = True
                    break
            obj_zip.close()
            if not class_found:
                return

        if int_version >= 210:
            if process['pid'] not in reported_PIDs_jvm:
                reported_PIDs_jvm.add(process['pid'])
                if process['jvm_args_enabled'] is True:
                    process['tag'] += 'jvm_args_fix,'
                    temp_fixed_PIDs[process['pid']] = True
                    print_msg('[Warning] You set jvm args to fix the Log4j vulnerability before, '
                              'please now update to {company} sec version')
                    print_msg('[Warning] Reference: http://mannual.domain/apache-log4j-rce-CVE-2021-45046')
            if process['pid'] not in reported_PIDs_sys_env:
                reported_PIDs_sys_env.add(process['pid'])
                if process['sys_env_enabled'] is True:
                    process['tag'] += 'sys_env_fix,'
                    temp_fixed_PIDs[process['pid']] = True
                    print_msg('[Warning] You set os environment variable to fix the Log4j vulnerability before, '
                              'please now update to {company} sec version')
                    print_msg('[Warning] Reference: http://mannual.domain/apache-log4j-rce-CVE-2021-45046')

        if process['pid'] not in temp_fixed_PIDs and process['pid'] not in reported_PIDs:
            reported_PIDs.add(process['pid'])
            process['tag'] += 'vulnerable,'
            print_msg('[Critical] Your server is vulnerable!')
            print_msg('[Critical] Java pid: %s, log4j2 path: %s' % (process['pid'], ancestor))
            if process['root_path'] != '':
                print_msg("[Critical] It's a docker container process, Image: %s" % process['docker_image'])
    except Exception as e:
        print_msg('[version_check.error]: %s' % str(e))


def get_container_image(pid):
    try:
        with open('/proc/%s/cgroup' % pid) as f:
            container_id = f.readline().split('/')[-1]
        image = get_cmd_out("docker inspect --format='{{.Config.Image}}' %s" % container_id)
        return image
    except Exception as e:
        # docker -> docker -> docker can fail, multiple level of docker will fail
        # for example, minikube related process will fail
        print_msg('[get_container_image.error]: %s' % str(e))
        return ""


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def upload_report():
    if report_url.strip() == '':
        return
    body = {"hostname": platform.node(), "ip": get_ip(), "process": process_lst, "token": "log4j.vul.sync"}

    for _ in range(5):    # retry on network error or api server error
        try:
            try:
                request = request_lib.Request(url=report_url, data=json.dumps(body),
                                              headers={'Content-Type': 'application/json'})
                request_lib.urlopen(request)
            except Exception as e:
                # python 3.x
                request = request_lib.Request(url=report_url, data=json.dumps(body).encode("utf-8"),
                                              headers={'Content-Type': 'application/json'})
                request_lib.urlopen(request)
            return
        except Exception as e:
            pass


if __name__ == '__main__':
    if not os.path.exists(TMP_DIR):
        os.mkdir(TMP_DIR)
    process_lst = get_all_java_process()
    if not process_lst:
        print_msg('No java process found, server not vulnerable at present.')
    else:
        print_msg('%s java process found' % len(process_lst))
        for process in process_lst:
            try:
                jar_count = get_jar_count(process)
                if jar_count > 0:
                    scan_jar_file(process)
            except Exception as e:    # short time process may exited
                pass
    # sleep random seconds, in case api server QPS too high and overload
    # if you run this script concurrently on 10k servers, you should sleep random * 10
    # time.sleep(random.random() * 10)
    upload_report()
    shutil.rmtree(TMP_DIR)
