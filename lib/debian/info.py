''' Сollecting information about packages (packages.debian.org) '''

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

def get_package_source(dom:etree._Element) -> str:
  ''' Parsing dom (packages.debian.org) and return package source '''
  select_xpath = '//div[@id="psource"]/a//text()'
  try:
    return dom.xpath(select_xpath)[0]
  except:
    return 'not found'

def replace_txt(txt:str) -> str:
  ''' Replace txt and return new txt '''
  new_txt = re.sub('[\n]+', ' ', txt)
  new_txt = re.sub('[\t]+', ' ', new_txt)
  new_txt = re.sub('^[ ]+', '', new_txt)
  new_txt = re.sub('[ ]+$', '', new_txt)
  new_txt = re.sub(';', '.', new_txt)
  return new_txt

def get_package_desc(dom:etree._Element) -> str:
  ''' Parsing dom (packages.debian.org) and return package description '''
  select_xpath = '//div[@id="pdesc"]/h2//text()'
  try:
    description = dom.xpath(select_xpath)[0]
  except:
    description = 'not found'
  return replace_txt(description)

def get_package_fdesc(dom:etree._Element) -> str:
  ''' Parsing dom (packages.debian.org) and return package full description '''
  select_xpath = '//div[@id="pdesc"]/p//text()'
  try:
    full_description = dom.xpath(select_xpath)[0]
  except:
    full_description = 'not found'
  return replace_txt(full_description)

def get_info(release:str, arch:str, package:str) -> dict:
  ''' Сollecting information about packages (packages.debian.org) '''
  url = 'https://packages.debian.org/{}/{}/{}'.format(release, arch, package)
  try:
    response = requests.get(url)
  except:
    return None
  if response.status_code == 200:
    html = response.text
    dom = convert_html(html, 'dom')
    pkg_source = get_package_source(dom)
    package_description = get_package_desc(dom)
    package_fdescription = get_package_fdesc(dom)
    package_info = {
      'package': package,
      'package_source': pkg_source,
      'package_arch': arch,
      'package_description': package_description,
      'package_fdescription': package_fdescription,
      'package_href': url
    }
  else:
    package_info = {
      'package': package,
      'package_source': None,
      'package_arch': arch,
      'package_description': 'N/A',
      'package_fdescription': 'N/A',
      'package_href': url
    }
  return package_info