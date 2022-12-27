#!/usr/bin/python3
'''
in:
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
        'soturation': {
          'VUL': {
            'cve': str,
            'description': str,
            'href': str,
            'href_api': str,
            'href_web': str,
            'date_published': str,
            'cvss2_score': str,
            'cvss2_access_vector': str,
            'cvss3_score': str,
            'cvss3_attack_vector': str,
            'status_vulners': str,
            'status_nessus': str
          },
          'SCA6': {
            'sca': str,
            'level': str
          }
  
          }
        }
      }, ... )
    }, ... )
  }

---------------------------------------------------------------------
-> distr: distr - дистрибутив
-> release: release - релиз дистрибутива
-> new_release: new_release - новый релиз дистрибутива
---------------------------------------------------------------------
-> packages -> package: package - имя пакета
-> packages -> package_source: package_source - имя исходного пакета
-> packages -> package_arch: package_arch - архитектура пакета
---------------------------------------------------------------------
-> packages -> issues -> cve: cve - индентификатор
-> packages -> issues -> tables: table - классификация уязвимости 
---------------------------------------------------------------------
-> packages -> issues -> current_version: current_version - текущая версия пакета
-> packages -> issues -> status_current_version: status_current_version - уязвимость в текущем пакете для текущего релиза
-> packages -> issues -> max_version -> max_version: max_version - максимальная версия пакета для текущего релиза
-> packages -> issues -> status_max_version: status_max_version - уязвимость для максимальной версии пакета для текущего релиза
-> packages -> issues -> new_version: new_version - последняя версия пакета для нового релиза
-> packages -> issues -> status_new_version: status_new_version - уязвимость для нового релиза
-> packages -> issues -> sid_version: sid_version - последняя версия пакета
-> packages -> issues -> status_sid_version: status_sid_version - наличие уязвимости в sid версии (последняя версия пакета)
---------------------------------------------------------------------
-> packages -> issues -> soturation -> VUL -> status_vulners: vulners_com - определение уязвимости через vulners.com
-> packages -> issues -> soturation -> VUL -> date_published: date_published - время публикации уязвимости
-> packages -> issues -> soturation -> VUL -> cvss2_score: cvss2_score - индекс cvss2
-> packages -> issues -> soturation -> VUL -> cvss2_access_vector: cvss2_access_vector - вектор доступа согласно cvss2
-> packages -> issues -> soturation -> VUL -> cvss3_score: cvss3_score - индекс cvss2
-> packages -> issues -> soturation -> VUL -> cvss3_attack_vector: cvss3_attack_vector - вектор атаки согласно cvss3
---------------------------------------------------------------------
-> packages -> issues -> soturation -> VUL -> status_nessus: nessus - определение уязвимости через nessus
---------------------------------------------------------------------
-> packages -> issues -> soturation -> SCA6 -> sca: sca6 - определение уязвимости через sca6
-> packages -> issue -> soturation -> SCA6 -> level: sca6_level - уровень уязвимости
---------------------------------------------------------------------
-> packages -> package_description: package_description - описание пакета
-> packages -> package_href: package_href - сылка на пакет
-> packages -> issues -> mini_description: cve_description - описание уязвимости
-> packages -> issues -> href: cve_href - сылка на уязвимость
---------------------------------------------------------------------
'''

import time
import re

import lib.file

def progress_bar(msg:str, line_break:bool=False) -> None:
  ''' print progress bar '''
  if line_break:
    print('>', msg, end='\n')
  else:
    print(' '*60, '|', end='\r')
    print('>', msg, end='\r')

def get_config() -> dict:
  ''' get config '''
  path = 'config/reportCSV.json'
  return lib.file.open_json(path)

def get_header_report() -> tuple:
  ''' get header csv '''
  header = (
    'distr',
    'release',
    'new_release',
    '',
    'package',
    'package_source',
    'package_arch',
    '',
    'cve',
    'table',
    '',
    'current_version',
    'status_current_version',
    'max_version',
    'status_max_version',
    'new_version',
    'status_new_version',
    'sid_version',
    'status_sid_version',
    '',
    'vulners_com',
    'date_published',
    'cvss2_score',
    'cvss2_access_vector',
    'cvss3_score',
    'cvss3_attack_vector',
    '',
    'nessus',
    '',
    'sca6',
    'sca6_level',
    '',
    'package_description',
    'package_href',
    'cve_description',
    'cve_href'
    )
  return header

def get_data_report(dataset:dict) -> tuple:
  ''' get data csv '''
  result = ()
  report_filter = ('Not found', 'fixed')

  for item in ('distr', 'release', 'new_release', 'packages'):
    if not item in dataset.keys():
      return None
  distr = dataset['distr']
  release = dataset['release']
  new_release = dataset['new_release']
  for package in dataset['packages']:
    package_name = package['package']
    progress_bar('add info: {}'.format(package_name))
    package_source = package['package_source']
    package_arch = package['package_arch']
    package_description = package['package_description']
    package_href = package['package_href']
    if not 'issues' in package:
      continue
    for pkg_issue in package['issues']:
      cve = pkg_issue['cve']
      table = pkg_issue['tables']
      # ---------------
      current_version = pkg_issue['current_version']
      status_current_version = pkg_issue['status_current_version']
      max_version = pkg_issue['max_version']
      status_max_version = pkg_issue['status_max_version']
      new_version = pkg_issue['new_version']
      status_new_version = pkg_issue['status_new_version']
      sid_version = pkg_issue['sid_version']
      status_sid_version = pkg_issue['status_sid_version']
      # ---------------
      try:
        vulners_com = pkg_issue['soturation']['VUL']['status_vulners']
      except:
        vulners_com = '-'
      try:
        date_published = pkg_issue['soturation']['VUL']['date_published']
      except:
        date_published = '-'
      try:
        cvss2_score = str(pkg_issue['soturation']['VUL']['cvss2_score'])
      except:
        cvss2_score = '-'
      try:
        cvss2_access_vector = pkg_issue['soturation']['VUL']['cvss2_access_vector']
      except:
        cvss2_access_vector = '-'
      try:
        cvss3_score = str(pkg_issue['soturation']['VUL']['cvss3_score'])
      except:
        cvss3_score = '-'
      try:
        cvss3_attack_vector = pkg_issue['soturation']['VUL']['cvss3_attack_vector']
      except:
        cvss3_attack_vector = '-'
      # ---------------
      try:
        nessus = pkg_issue['soturation']['VUL']['status_nessus']
      except:
        nessus = '-'
      # ---------------
      try:
        sca6 = pkg_issue['soturation']['SCA6']['sca']
      except:
        sca6 = '-'
      try:
        sca6_level = pkg_issue['soturation']['SCA6']['level']
      except:
        sca6_level = '-'
      # ---------------
      package_description = package['package_description']
      package_href = package['package_href']
      cve_description = pkg_issue['mini_description']
      try:
        cve_href = pkg_issue['href']
      except:
        cve_href = 'https://security-tracker.debian.org/tracker/{}'.format(cve)
      # ---------------

      data = (
        distr,
        release,
        new_release,
        '',
        package_name,
        package_source,
        package_arch,
        '',
        cve,
        table,
        '',
        current_version,
        status_current_version,
        max_version,
        status_max_version,
        new_version,
        status_new_version,
        sid_version,
        status_sid_version,
        '',
        vulners_com,
        date_published,
        cvss2_score,
        cvss2_access_vector,
        cvss3_score,
        cvss3_attack_vector,
        '',
        nessus,
        '',
        sca6,
        sca6_level,
        '',
        package_description,
        package_href,
        cve_description,
        cve_href,
      )
      status_report_commit = True
      for item in report_filter:
        if item in status_max_version:
          status_report_commit = False
      if status_report_commit:
        result += (data, )
  return result

def main() -> bool:
  ''' main '''
  progress_bar('read config ...')
  config = get_config()
  file_db_target = config['input']
  file_report = config['output']
  
  progress_bar('open report target: {}.json'.format(file_db_target))
  db_target = lib.file.open_json('{}.json'.format(file_db_target))

  progress_bar('create table ...')
  header = get_header_report()
  data = get_data_report(db_target)

  progress_bar('save csv report: {}.csv'.format(file_report))
  lib.file.save_csv('{}.csv'.format(file_report), header, data)
  exit(0)

if __name__ == "__main__":
  main()