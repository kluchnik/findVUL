#!/usr/bin/python3

import time
import re

import lib.file

from lib.vulners_com.check import get_cve_info

def progress_bar(msg:str, line_break:bool=True) -> None:
  ''' print progress bar '''
  if line_break:
    print('>', msg, end='\n')
  else:
    print(' '*60, '|', end='\r')
    print('>', msg, end='\r')

def get_config() -> dict:
  ''' get config '''
  path = 'config/soturationVUL.json'
  return lib.file.open_json(path)

def main() -> bool:
  ''' main '''
  progress_bar('read config ...')
  config = get_config()
  file_db_target = config['input']
  file_db_output = config['output']
  api_key = config['api_key']
  
  progress_bar('open report target: {}.json'.format(file_db_target))
  db_target = lib.file.open_json('{}.json'.format(file_db_target))
  '''
  db_target = {
    'distr': str,
    'release': str,
    'new_release': str,
    'packages': (
    {
      'package': str,
      'package_source': str,
      'package_arch': str,
      'package_description': str,
      'package_fdescription': str,
      'package_href': str,
      'issues': ({
        'cve': str,
        'tables': str,
        'description': str,
        'mini_description': str,
        'description': str,
        'current_version': str,
        'status_current_version': str,
        'max_version': str,
        'status_max_version': str,
        'new_version': str,
        'status_new_version': str,
        'sid_version': str,
        'status_sid_version': str,
        'soturation': {}
      }, ... )
    }, ... )
  }
  '''
  distr = db_target['distr']
  release = db_target['release']
  for package in db_target['packages']:
    package_source = package['package_source']
    progress_bar('soturation VUL ({})'.format(package_source))
    for item in range(len(package['issues'])):
      cve = package['issues'][item]['cve']
      status_max_version = package['issues'][item]['status_max_version']
      progress_bar('get information vulners.com ({})'.format(cve))
      for vulnerable in ('vulnerable', 'undetermined'):
        if vulnerable in status_max_version:
          data_VUL = get_cve_info(api_key, distr, release, cve)
          break
        else:
          data_VUL = {}
      package['issues'][item]['soturation']['VUL'] = data_VUL
  
  progress_bar('save database soturation target: {}.json'.format(file_db_output))
  lib.file.save_json('{}.json'.format(file_db_output), db_target)

if __name__ == "__main__":
  main()