''' Test lib/debian/vulners.py '''

import pytest
from lxml import etree

import lib.file
from lib.debian.vulners import convert_html
from lib.debian.vulners import get_tables
from lib.debian.vulners import get_cve
from lib.debian.vulners import get_mini_description

@pytest.fixture
def get_html_page(scope="module") -> str:
  ''' Open and return http page '''
  FILE_HTML_PAGE = 'test/debian/example_vulners.html'
  html = lib.file.open_f(FILE_HTML_PAGE)
  yield html

def test_open_html_page(get_html_page:str):
  ''' Open file html page '''
  assert get_html_page != None

def test_html_to_dom(get_html_page:str):
  ''' Convert html txt to dom object '''
  dom = convert_html(get_html_page, 'dom')
  assert type(dom) is etree._Element

def test_get_tables(get_html_page:str):
  ''' Test parsing dom (security-tracker.debian.org) and return table name '''
  dom = convert_html(get_html_page, 'dom')
  tables = get_tables(dom)
  expectations = ('Available versions',
    'Open unimportant issues',
    'Resolved issues',
    'Security announcements')
  for expectation in expectations:
    assert expectation in tables


@pytest.mark.parametrize('table,expectation', [
  (None, ('CVE-2013-0340', 'CVE-2022-43680', 'CVE-2022-40674', 'CVE-2022-25315',
    'CVE-2022-25314', 'CVE-2022-25313', 'CVE-2022-25236', 'CVE-2022-25235',
    'CVE-2022-23990', 'CVE-2022-23852', 'CVE-2022-22827', 'CVE-2022-22826',
    'CVE-2022-22825', 'CVE-2022-22824', 'CVE-2022-22823', 'CVE-2022-22822',
    'CVE-2021-46143', 'CVE-2021-45960', 'CVE-2019-15903', 'CVE-2018-20843',
    'CVE-2017-11742', 'CVE-2017-9233', 'CVE-2016-9063', 'CVE-2016-5300',
    'CVE-2016-4472', 'CVE-2016-0718', 'CVE-2015-1283', 'CVE-2012-6702',
    'CVE-2012-1148', 'CVE-2012-1147', 'CVE-2012-0876', 'CVE-2009-3720',
    'CVE-2009-3560')),
  ('Available versions', ()),
  ('Open unimportant issues', ('CVE-2013-0340',)),
  ('Resolved issues', ('CVE-2022-43680', 'CVE-2022-40674', 'CVE-2022-25315',
    'CVE-2022-25314', 'CVE-2022-25313', 'CVE-2022-25236', 'CVE-2022-25235',
    'CVE-2022-23990', 'CVE-2022-23852', 'CVE-2022-22827', 'CVE-2022-22826',
    'CVE-2022-22825', 'CVE-2022-22824', 'CVE-2022-22823', 'CVE-2022-22822',
    'CVE-2021-46143', 'CVE-2021-45960', 'CVE-2019-15903', 'CVE-2018-20843',
    'CVE-2017-11742', 'CVE-2017-9233', 'CVE-2016-9063', 'CVE-2016-5300',
    'CVE-2016-4472', 'CVE-2016-0718', 'CVE-2015-1283', 'CVE-2012-6702',
    'CVE-2012-1148', 'CVE-2012-1147', 'CVE-2012-0876', 'CVE-2009-3720',
    'CVE-2009-3560')),
  ('Security announcements', ()),
  ('N/A', ()),
  ]) 
def test_get_cve(get_html_page:str, table:str, expectation:tuple):
  ''' Test parsing dom (security-tracker.debian.org) and return CVE '''
  dom = convert_html(get_html_page, 'dom')
  cve = get_cve(dom, table)
  assert cve == expectation


@pytest.mark.parametrize('cve,expectation', [
  ('CVE-2013-0340', ('expat 2.1.0 and earlier does not properly handle entities expansion un ...',)),
  ('CVE-2022-43680', ('In libexpat through 2.4.9, there is a use-after free caused by overeag ...',)),
  ('CVE-2019-15903', ('In libexpat before 2.2.8, crafted XML input could fool the parser into ...',)),
  ('CVE-2009-3560', ('The big2_toUtf8 function in lib/xmltok.c in libexpat in Expat 2.0.1, a ...',))
  ])
def test_get_mini_description(get_html_page:str, cve:str, expectation:str):
  ''' Test parsing dom (security-tracker.debian.org) and minimal description '''
  dom = convert_html(get_html_page, 'dom')
  description = get_mini_description(dom, cve)
  assert description == expectation[0]
