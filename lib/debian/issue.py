''' vulnerability check on security-tracker.debian.org website '''

import requests
import re

try:
  from BeautifulSoup import BeautifulSoup
except ImportError:
  from bs4 import BeautifulSoup

from lxml import etree


def convert_html(html:str, _type:str='dom') -> object:
  ''' Convert html to [soup|dom] '''
  soup = BeautifulSoup(html, 'html.parser')
  dom = etree.HTML(str(soup))
  if _type == 'dom':
    return dom
  elif _type == 'soup':
    return soup
  else:
    return None

def replace_txt(txt:str) -> str:
  ''' Replace txt and return new txt '''
  new_txt = re.sub('[\n]+', ' ', txt)
  new_txt = re.sub('[\t]+', ' ', new_txt)
  new_txt = re.sub('^[ ]+', '', new_txt)
  new_txt = re.sub('[ ]+$', '', new_txt)
  new_txt = re.sub(';', '.', new_txt)
  return new_txt

def get_description(dom:etree._Element) -> str:
  ''' Parsing dom (security-tracker.debian.org) and return description '''
  select_xpath = '//table//b[text()="Description"]/../../td[last()]//text()'
  try:
    description = dom.xpath(select_xpath)[0]
  except:
    description = 'not found'
  description = replace_txt(description)
  return description

def get_version_status(dom:etree._Element, version:str) -> str:
  ''' Parsing dom (security-tracker.debian.org) and return status on version '''
  select_xpath = '//*[contains(text(),"{}")]//following::td[1]//text()'.format(version)
  try:
    return dom.xpath(select_xpath)[0]
  except:
    return 'not found'

def get_packages(dom:etree._Element) -> tuple:
  ''' Parsing dom (security-tracker.debian.org) and return package name '''
  select_xpath = '//table//th[text()="Source Package"]\
/../..//a[contains(@href,"/source-package/")]//text()'
  try:
    return tuple(dom.xpath(select_xpath))
  except:
    return ()

def get_package_line(dom:etree._Element, package:str) -> int:
  '''
  Parsing dom (security-tracker.debian.org) and returns the table 
  "Source Package" package line
  '''
  select_xpath = 'count(//table//th[text()="Source Package"]\
/../..//a[text()="{}"]/../../preceding-sibling::tr)'.format(package)
  try:
    return int(dom.xpath(select_xpath))
  except:
    return 1

def get_max_line(dom:etree._Element) -> int:
  '''
  Parsing dom (security-tracker.debian.org) and returns the table 
  "Source Package" max package line
  '''
  select_xpath = 'count(//table//th[text()="Source Package"]/../..//tr)'
  try:
    return int(dom.xpath(select_xpath))
  except:
    return 1

def get_table_row_number(dom:etree._Element) -> dict:
  '''
  Parsing dom (security-tracker.debian.org) and returns the table 
  "Source Package" row number by batch
  example: CVE-2018-5389
  out: {
        'isakmpd': {'start': 1, 'end': 3},
        'libreswan': {'start': 3, 'end': 6},
        'strongswan': {'start': 6, 'end': 11}
       }
  '''
  output = {}
  packages = get_packages(dom)
  '''
  example: CVE-2018-5389
  packages = ('isakmpd', 'libreswan', 'strongswan')
  '''
  for item in range(len(packages)):
    if item == 0:
      # first element
      output[packages[item]] = {}
      output[packages[item]]['start'] = 1
      if len(packages) >= 2:
        output[packages[item]]['end'] = get_package_line(dom, packages[item+1])
      else:
        output[packages[item]]['end'] = get_max_line(dom)
    elif item == len(packages)-1:
      # last element
      output[packages[item]] = {}
      output[packages[item]]['start'] = get_package_line(dom, packages[item])
      output[packages[item]]['end'] = get_max_line(dom)
    else:
      # middle element
      output[packages[item]] = {}
      output[packages[item]]['start'] =  get_package_line(dom, packages[item])
      output[packages[item]]['end'] =  get_package_line(dom, packages[item+1])
  return output

def get_pkg_ver_status(dom:etree._Element, release:str) -> dict:
  '''
  Parsing dom (security-tracker.debian.org) and return package versions 
  and vulnerables from the table
  example: CVE-2018-5389
  in:  'buster'
  out: {
         'libreswan': {'3.27-6+deb10u1': 'vulnerable'},
         'isakmpd': {'20041012-8': 'vulnerable'},
         'strongswan': {
           '5.7.2-1+deb10u2': 'vulnerable',
           '5.7.2-1+deb10u3': 'vulnerable'
          }
       }
  '''
  output = {}
  row_number = get_table_row_number(dom)
  '''
  example: CVE-2018-5389
  row_number = {
    'isakmpd': {'start': 1, 'end': 3},
    'libreswan': {'start': 3, 'end': 6},
    'strongswan': {'start': 6, 'end': 11}
  }
  '''
  for package in row_number.keys():
    output[package] = {}
    start_row = row_number[package]['start']
    end_row = row_number[package]['end']
    select_xpath = '//table//th[text()="Source Package"]\
/../..//tr[position()>{} and position()<={}]\
/td[contains(text(),"{}")]/../td[3]//text()'.format(start_row, end_row, release)
    try:
      versions = tuple(dom.xpath(select_xpath))
    except:
      versions = ()
    select_xpath = '//table//th[text()="Source Package"]\
/../..//tr[position()>{} and position()<={}]\
/td[contains(text(),"{}")]/../td[4]//text()'.format(start_row, end_row, release)
    try:
      vulnerables = tuple(dom.xpath(select_xpath))
    except:
      vulnerables = ()
    if versions != ():
      for item in range(len(versions)):
        try:
          output[package][versions[item]] = vulnerables[item]
        except:
          output[package][versions[item]] = 'N/A'
    else:
      output[package]['not found'] = 'not found'
  return output

def version_comparison(first_ver:str, second_ver:str) -> bool:
  ''' Package version comparison, if first_ver > second_ver return True else False '''
  default_separators = (':', '.', '+', '~')
  first_ver = re.sub('[a-zA-Z-$]*', '', first_ver)
  second_ver = re.sub('[a-zA-Z-$]*', '', second_ver)
  for item in default_separators:
    if item in first_ver and item in second_ver:
      first_ver = first_ver.replace(item, ';')
      second_ver = second_ver.replace(item, ';')
    elif item in first_ver and not item in second_ver:
      second_ver = second_ver.replace(item, '')
    elif not item in first_ver and item in second_ver:
      first_ver = first_ver.replace(item, '')
  first_ver = first_ver.split(';')
  second_ver = second_ver.split(';')
  for item in range(len(first_ver)):
    try:
      first_int = int(first_ver[item])
      second_int = int(second_ver[item])
      if first_int > second_int:
        return True
      elif first_int < second_int:
        return False
    except:
      pass
  return False

def get_max_version_and_status(dom:etree._Element, source_package:str, release:str) -> list:
  ''' Parsing dom (security-tracker.debian.org) and return max version and status '''
  pkg_ver_status = get_pkg_ver_status(dom, release)
  '''
  example: CVE-2018-5389
  pkg_ver_status = {
         'libreswan': {'3.27-6+deb10u1': 'vulnerable'},
         'isakmpd': {'20041012-8': 'vulnerable'},
         'strongswan': {
           '5.7.2-1+deb10u2': 'vulnerable',
           '5.7.2-1+deb10u3': 'vulnerable'
          }
       }
  '''
  if not source_package in pkg_ver_status.keys():
    return 'N/A','N/A'
  versions = tuple(pkg_ver_status[source_package].keys())
  max_version = versions[0] if len(versions) > 0 else 'N/A'
  for version in versions:
    if version_comparison(version, max_version):
      max_version = version
  try:
    status = pkg_ver_status[source_package][max_version]
  except:
    status = 'N/A'
  return max_version,status

def get_cve_info(cve:str, source_package:str, release:str=None, new_release:str=None, current_version:str=None) -> dict:
  ''' Returns vulnerability data by CVE (security-tracker.debian.org) '''
  url = 'https://security-tracker.debian.org/tracker/{}'.format(cve)
  try:
    response = requests.get(url)
  except:
    return None
  if response.status_code == 200:
    html = response.text
    dom = convert_html(html, 'dom')
    max_version_stat, status_max_version = get_max_version_and_status(dom, source_package, release)
    new_version, status_new_version = get_max_version_and_status(dom, source_package, new_release)
    sid_version, status_sid_version = get_max_version_and_status(dom, source_package, 'sid')
    return {
      'cve': cve,
      'description': get_description(dom),
      'href': url,
      'current_version': current_version,
      'status_current_version': get_version_status(dom, current_version),
      'max_version': max_version_stat,
      'status_max_version': status_max_version,
      'new_version': new_version,
      'status_new_version': status_new_version,
      'sid_version': sid_version,
      'status_sid_version': status_sid_version
    }
  else:
    return {
      'cve': cve,
      'description': 'N/A',
      'href': url,
      'current_version': current_version,
      'status_current_version': 'N/A',
      'max_version': 'N/A',
      'status_max_version': 'N/A',
      'new_version': 'N/A',
      'status_new_version': 'N/A',
      'sid_version': 'N/A',
      'status_sid_version': 'N/A'
    }