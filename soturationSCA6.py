#!/usr/bin/python3

import time
import re

import lib.file

def progress_bar(msg:str, line_break:bool=True) -> None:
  ''' print progress bar '''
  if line_break:
    print('>', msg, end='\n')
  else:
    print(' '*60, '|', end='\r')
    print('>', msg, end='\r')

def get_config() -> dict:
  ''' get config '''
  path = 'config/soturationSCA6.json'
  return lib.file.open_json(path)

def main() -> bool:
  ''' main '''
  progress_bar('read config ...')
  config = get_config()
  file_db_target = config['input_target']
  file_db_sca6 = config['input_sca6']
  file_db_output = config['output']
  
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
  
  progress_bar('open report sca6: {}.json'.format(file_db_sca6))
  db_sca6 = lib.file.open_json('{}.json'.format(file_db_sca6))
  '''
  db_sca6 = {
    'distr': '...',
    'release': '...',
    'vulners': (
    {
      'CVE': 'CVE-...',
      'sca6_level': '...',
      'sca6_package': '...',
      'sca6_version': '...',
      'sca6_description': '...'
      'description': '...',
      'href': '...',
      'packages': ['...','...'],
      'versions': ['...','...'],
      'vulnerables': ['...','...'],
      'check': '...'
    }, ... )
  }
  '''

  progress_bar('soturation SCA6 ...')
  for vulner in db_sca6['vulners']:
    sca6_package_name = vulner['sca6_package']
    sca6_cve = vulner['cve']
    sca6_level = vulner['sca6_level']
    sca6_description = vulner['sca6_description']
    progress_bar('get information sca6 ({})'.format(sca6_cve))
    for package in db_target['packages']:
      deb_package_name = package['package']
      deb_source_name = package['package_source']
      for item in range(len(package['issues'])):
        deb_cve = package['issues'][item]['cve']
        if \
        (sca6_package_name in deb_package_name or \
        sca6_package_name in deb_source_name) and \
        sca6_cve == deb_cve:
          package['issues'][item]['soturation']['SCA6'] = {
            'sca': 'yes',
            'level': sca6_level
          }

  progress_bar('save database soturation target: {}.json'.format(file_db_output))
  lib.file.save_json('{}.json'.format(file_db_output), db_target)

if __name__ == "__main__":
  main()