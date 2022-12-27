''' parsing html report sca6 '''

try:
  from BeautifulSoup import BeautifulSoup
except ImportError:
  from bs4 import BeautifulSoup
from lxml import etree

import lib.file

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

def open_html_report(path:str) -> str:
  ''' Open html report file '''
  return lib.file.open_f(path)

def parsing_small_report(path:str) -> list:
  ''' Parsing small html report sca6 '''
  result = ()
  html = open_html_report(path)
  dom = convert_html(html, 'dom')
  select_xpath = '//table[@class="table"]/tbody//td[contains(text(),"CVE-")]/text()'
  cve_list = dom.xpath(select_xpath)
  for cve in cve_list:
    result += ({
      'cve': cve,
      'sca6_level': None,
      'sca6_package': None,
      'sca6_version': None,
      'sca6_description': None
    }, )
  return result

def get_cve(dom:'lxml.etree._Element') -> list:
  ''' Parsing the dom full report and return CVEs '''
  select_xpath = '//table[@class="table-vulnerabilities"]\
/tbody//td[@class="table-vulnerabilities__cell"][contains(text(),"CVE-")]/text()'
  return dom.xpath(select_xpath)

def replace_null_td(html:str) -> str:
  ''' Replacing a null value in a table (td) '''
  old_str = '<td class="table-vulnerabilities__cell"></td>'
  new_str = '<td class="table-vulnerabilities__cell">-</td>'
  return html.replace(old_str, new_str)

def parsing_full_report(path:str) -> tuple:
  ''' Parsing full html report sca6 '''
  result = ()
  html = open_html_report(path)
  html = replace_null_td(html)
  dom = convert_html(html, 'dom')
  select_xpath = '//table[@class="table-vulnerabilities"]/tbody//td[3]/text()'
  metadata = dom.xpath(select_xpath)[2:]
  for item in range(0, len(metadata), 10):
    try:
      cve = metadata[item]
    except:
      cve = 'N/A'
    try:
      level = metadata[item+2]
    except:
      level = 'N/A'
    try:
      pkg_and_vers = metadata[item+3]
    except:
      pkg_and_vers = 'N/A'
    try:
      package = pkg_and_vers.split(' ')[0]
      version = pkg_and_vers.split(' ')[1]
    except:
      package = pkg_and_vers
      version = 'N/A'
    try:
      description = metadata[item+9]
    except:
      description = 'N/A'
    result += ({
      'cve': cve,
      'sca6_level': level,
      'sca6_package': package,
      'sca6_version': version,
      'sca6_description': description.replace(';','.').replace('\n','|-> ')
    }, )
  return result
