#!/usr/bin/python3

import time

import lib.ssh
import lib.file
from lib.debian.info import get_info
from lib.debian.vulners import get_vulners
from lib.debian.issue import get_cve_info as get_cve_info

def progress_bar(msg:str, line_break:bool=True) -> None:
  ''' print progress bar '''
  if line_break:
    print('>', msg, end='\n')
  else:
    print(' '*60, '|', end='\r')
    print('>', msg, end='\r')
  #print('\r\033[K> {}'.format(msg), end=' ')

def get_config() -> dict:
  ''' get config '''
  path = 'config/findVULdeb.json'
  return lib.file.open_json(path)

def get_cmd(distr:str) -> str:
  ''' Returns a command to get a list of packages '''
  if distr == 'debian':
    cmd = 'dpkg-query -W -f=\'${Status} ${Package} ${Version} ${Architecture}\\n\' | \
awk \'($1 == "install") && ($2 == "ok") {print $4" "$5" "$6}\''
  elif distr == 'debian-kernel':
    cmd = '''
    k_info=$(uname -a | awk '{print $3}')
    k_name=$(echo linux-headers-${k_info})
    k_arch=$(echo ${k_info} | sed -r 's/^[0-9.]*-[0-9.]*-//')
    k_version=$(echo ${k_info} | sed -r 's/-'${k_arch}'$//')
    echo ${k_name} ${k_version} ${k_arch}
    '''
  else:
    cmd = ''
  return cmd

def get_ssh_pkg_list(cfg_ssh:dict, distr:str) -> dict:
  '''Connect via ssx to get a list of packages '''
  pc = lib.ssh.UNION()
  if pc.set_connParam(**cfg_ssh):
    if pc.connect():
      cmd = get_cmd(distr)
      if pc.run_command(cmd):
        stdout = pc.get_line_std('stdout')
        stderr = pc.get_line_std('stderr')
      else:
        stdout = ('',)
        stderr = ('failed to execute ssh command',)
    else:
      stdout = ('',)
      stderr = ('failed to connect via ssh',)
  else:
    stdout = ('',)
    stderr = ('failed to set ssh connection parameters',)
  return {'stdout': stdout, 'stderr': stderr}

def get_info_multi(release:str, pkg_arch:str, pkg_name:str) -> dict:
  ''' Сollecting information about packages (packages.debian.org) '''
  timeout = 60
  max_count = 5
  for item in range(max_count):
    pkg_info = get_info(release, pkg_arch, pkg_name)
    if pkg_info:
      break
    else:
      print('ERROR:', 'TIMEOUT PACKAGE INFO -', release, pkg_arch, pkg_name)
      time.sleep(timeout)
  return pkg_info

def get_vulners_multi(pkg_source:str, pkg_ver:str) -> dict:
  ''' Searching for vulnerabilities (security-tracker.debian.org) '''
  timeout = 60
  max_count = 5
  for item in range(max_count):
    pkg_vulners = get_vulners(pkg_source, pkg_ver)
    if pkg_vulners != None:
      break
    else:
      print('ERROR:', 'TIMEOUT VULNERS LIST -', pkg_source, pkg_ver)
      time.sleep(timeout)
  return pkg_vulners

def get_cve_info_multi(cve:str, pkg_source:str, release:str, new_release:str, current_version:str) -> dict:
  ''' Get info CVE (security-tracker.debian.org) '''
  timeout = 60
  max_count = 5
  for item in range(max_count):
    cve_info = get_cve_info(cve, pkg_source, release, new_release, current_version)
    if cve_info:
      break
    else:
      print('ERROR:', 'TIMEOUT CVE INFO -', cve)
      time.sleep(timeout)
  return cve_info

def collection_pkg_issues(pkg_list:tuple, distr:str, release:str, new_release:str) -> tuple:
  ''' Collection of information about the package and its vulnerabilities '''
  result = {
    'distr': distr,
    'release': release,
    'new_release': new_release,
    'packages': ()
  }
  for pkg in pkg_list:
    progress_bar('get package info: {}'.format(pkg))
    try:
      pkg_name, pkg_ver, pkg_arch = pkg.split(' ')
    except:
      continue
    # Запросить информацию о пакете с сайта:
    # https://packages.debian.org/(release)/(arch)/(package)
    pkg_info = get_info_multi(release, pkg_arch, pkg_name)
    if not pkg_info:
      print('ERROR:', 'GET INFO -', pkg)
      break
    # Запросит информацию по уязвимостям для пакета с сайта:
    # https://security-tracker.debian.org/tracker/source-package/(package_source)
    pkg_source = pkg_info['package_source']
    progress_bar('get vulners: {} {}'.format(pkg_source, pkg_ver))
    pkg_vulners = get_vulners_multi(pkg_source, pkg_ver)
    # Добавление информации об уязвимостях
    for item in range(len(pkg_vulners)):
      cve = pkg_vulners[item]['cve']
      current_version = pkg_vulners[item]['current_version']
      progress_bar('get info: {} {}'.format(pkg_source, cve))
      cve_info = get_cve_info_multi(cve, pkg_source, release, new_release, current_version)
      pkg_vulners[item]['description'] = cve_info['description']
      pkg_vulners[item]['href'] = cve_info['href']
      pkg_vulners[item]['current_version'] = cve_info['current_version']
      pkg_vulners[item]['status_current_version'] = cve_info['status_current_version']
      pkg_vulners[item]['max_version'] = cve_info['max_version']
      pkg_vulners[item]['status_max_version'] = cve_info['status_max_version']
      pkg_vulners[item]['new_version'] = cve_info['new_version']
      pkg_vulners[item]['status_new_version'] = cve_info['status_new_version']
      pkg_vulners[item]['sid_version'] = cve_info['sid_version']
      pkg_vulners[item]['status_sid_version'] = cve_info['status_sid_version']
    # Добавить информацию о пакате
    package = {
      'package': pkg_info['package'],
      'package_source': pkg_info['package_source'],
      'package_arch': pkg_info['package_arch'],
      'package_description': pkg_info['package_description'],
      'package_fdescription': pkg_info['package_fdescription'],
      'package_href': pkg_info['package_href'],
      'issues': pkg_vulners
    }
    result['packages'] += (package, )
  return result

def main() -> bool:
  ''' main '''
  progress_bar('read config ...')
  config = get_config()
  distr = config['target']['distr']
  release = config['target']['release']
  new_release = config['target']['new_release']
  input_type = config['input_type']
  output_db = config['output']['db']
  # Получить список пакетов и версии
  progress_bar('get package list ...')
  if input_type == 'ssh':
    cfg_ssh = config['input']['ssh']
    pkg_list = get_ssh_pkg_list(cfg_ssh, '{}-kernel'.format(distr))['stdout']
    pkg_list += get_ssh_pkg_list(cfg_ssh, distr)['stdout']
  elif input_type == 'file':
    pass
  else:
    exit(1)
  # Запрос информации о уязвимостей в пакетах
  progress_bar('get package data ...')
  db_target = collection_pkg_issues(pkg_list, distr, release, new_release)
  # Созранение информации в файл
  progress_bar('save database target: {}.json'.format(output_db))
  lib.file.save_json('{}.json'.format(output_db), db_target)
  exit(0)

if __name__ == "__main__":
  main()