''' Сollecting vulnerabilities about packages (security-tracker.debian.org) '''

import requests

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

def get_tables(dom:etree._Element) -> tuple:
  ''' Parsing dom (security-tracker.debian.org) and return table name '''
  select_xpath = '//h2/text()'
  try:
    return tuple(dom.xpath(select_xpath))
  except:
    return ()

def get_cve(dom:etree._Element, table:str=None) -> tuple:
  ''' Parsing dom (security-tracker.debian.org) and return CVE '''
  if not table:
    select_xpath = '//a[contains(text(),"CVE-")]//text()'
  else:
    select_xpath = '//h2[text()="{}"]/following::table[1]//a[contains(text(),"CVE-")]//text()'.format(table)
  try:
    return tuple(dom.xpath(select_xpath))
  except:
    return ()

def get_mini_description(dom:etree._Element, cve:str, table:str=None) -> str:
  ''' Parsing dom (security-tracker.debian.org) and minimal description '''
  if not table:
    select_xpath = '//a[text()="{}"]/../../td[last()]//text()'.format(cve)
  else:
    select_xpath = '//a[text()="{}"]/../../\
td[count(//h2[text()="{}"]/following::table[1]//tr[1]/th)]//text()'.format(cve, table)
  try:
    return tuple(dom.xpath(select_xpath))[0]
  except:
    return 'not found'

def get_vulners(package_source:str, current_version:str) -> dict:
  ''' Searching for vulnerabilities (security-tracker.debian.org) '''
  url = 'https://security-tracker.debian.org\
/tracker/source-package/{}'.format(package_source)
  try:
    response = requests.get(url)
  except:
    return None
  if response.status_code == 200:
    html = response.text
    dom = convert_html(html, 'dom')
    # get table name
    tables = get_tables(dom)
    package_vulners = ()
    for table in tables:
      # get cve from table
      issues = get_cve(dom, table)
      # add cve
      for cve in issues:
        package_vulners += ({
          'cve': cve,
          'tables': table,
          'mini_description': get_mini_description(dom, cve),
          'description': 'N/A',
          'href': 'https://security-tracker.debian.org/tracker/{}'.format(cve),
          'current_version': current_version,
          'status_current_version': 'N/A',
          'max_version': 'N/A',
          'status_max_version': 'N/A',
          'new_version': 'N/A',
          'status_new_version': 'N/A',
          'sid_version': 'N/A',
          'status_sid_version': 'N/A',
          'soturation': {}
          },)
  else:
    print('ERORR:', response.status_code)
    package_vulners = ()
  return package_vulners
