''' Test lib/debian/issue.py '''

import pytest
from lxml import etree

import lib.file
from lib.debian.issue import convert_html
from lib.debian.issue import get_description
from lib.debian.issue import get_version_status
from lib.debian.issue import get_packages
from lib.debian.issue import get_package_line
from lib.debian.issue import get_max_line
from lib.debian.issue import get_table_row_number
from lib.debian.issue import get_pkg_ver_status
from lib.debian.issue import version_comparison
from lib.debian.issue import get_max_version_and_status


@pytest.fixture
def get_html_page(scope="module") -> str:
  ''' Open and return http page '''
  FILE_HTML_PAGE = 'test/debian/example_issue.html'
  html = lib.file.open_f(FILE_HTML_PAGE)
  yield html


def test_open_html_page(get_html_page:str):
  ''' Open file html page '''
  assert get_html_page != None

def test_html_to_dom(get_html_page:str):
  ''' Convert html txt to dom object '''
  dom = convert_html(get_html_page, 'dom')
  assert type(dom) is etree._Element

def test_get_description(get_html_page:str):
  ''' Test parsing dom (security-tracker.debian.org) and return description '''
  dom = convert_html(get_html_page, 'dom')
  description = get_description(dom)
  expectation = 'The Internet Key Exchange v1 main mode is vulnerable to offline \
dictionary or brute force attacks. Reusing a key pair across different versions \
and modes of IKE could lead to cross-protocol authentication bypasses. It is well \
known, that the aggressive mode of IKEv1 PSK is vulnerable to offline dictionary \
or brute force attacks. For the main mode, however, only an online attack against \
PSK authentication was thought to be feasible. This vulnerability could allow an \
attacker to recover a weak Pre-Shared Key or enable the impersonation of a victim \
host or network.'
  assert description == expectation


@pytest.mark.parametrize('version,expectation', [
  ('20041012-8', 'vulnerable'),
  ('20041012-10', 'vulnerable'),
  ('3.27-6+deb10u1', 'vulnerable'),
  ('4.3-1+deb11u1', 'vulnerable'),
  ('4.7-1', 'vulnerable'),
  ('5.7.2-1+deb10u2', 'vulnerable'),
  ('5.7.2-1+deb10u3', 'vulnerable'),
  ('5.9.1-1+deb11u2', 'vulnerable'),
  ('5.9.1-1+deb11u3', 'vulnerable'),
  ('5.9.8-3', 'vulnerable'),
  ('N/A', 'not found')
  ])
def test_get_version_status(get_html_page:str, version:str, expectation:str):
  ''' Test parsing dom (security-tracker.debian.org) and return description '''
  dom = convert_html(get_html_page, 'dom')
  status = get_version_status(dom, version)
  assert status == expectation

def test_get_packages(get_html_page:str):
  ''' Test parsing dom (security-tracker.debian.org) and return package name '''
  dom = convert_html(get_html_page, 'dom')
  packages = get_packages(dom)
  expectation = ('isakmpd', 'libreswan', 'strongswan')
  for package in expectation:
    assert package in packages


@pytest.mark.parametrize('package,expectation', [
  ('isakmpd', 1),
  ('libreswan', 3),
  ('strongswan', 6)
  ])
def test_get_package_line(get_html_page:str, package:str, expectation:str):
  '''
  Test parsing dom (security-tracker.debian.org) and returns the table 
  "Source Package" package line
  '''
  dom = convert_html(get_html_page, 'dom')
  package_line = get_package_line(dom, package)
  assert package_line == expectation

def test_get_max_line(get_html_page:str):
  '''
  Test parsing dom (security-tracker.debian.org) and returns the table 
  "Source Package" max package line
  '''
  dom = convert_html(get_html_page, 'dom')
  max_line_tables = get_max_line(dom)
  assert max_line_tables == 11


def test_get_table_row_number(get_html_page:str):
  '''
  Test parsing dom (security-tracker.debian.org) and returns the table 
  "Source Package" row number by batch
  '''
  dom = convert_html(get_html_page, 'dom')
  table_row_number = get_table_row_number(dom)
  expectation = {
    'isakmpd': {'start': 1, 'end': 3},
    'libreswan': {'start': 3, 'end': 6},
    'strongswan': {'start': 6, 'end': 11}
  }
  for package in table_row_number.keys():
    assert package in expectation
    assert table_row_number[package]['start'] == expectation[package]['start']
    assert table_row_number[package]['end'] == expectation[package]['end']


@pytest.mark.parametrize('release,expectation', [
  ('buster', {
    'isakmpd': {'20041012-8': 'vulnerable'},
    'libreswan': {'3.27-6+deb10u1': 'vulnerable'},
    'strongswan': {'5.7.2-1+deb10u2': 'vulnerable', '5.7.2-1+deb10u3': 'vulnerable'}
  }),
  ('bullseye', {
    'isakmpd': {'not found': 'not found'},
    'libreswan': {'4.3-1+deb11u1': 'vulnerable'},
    'strongswan': {'5.9.1-1+deb11u2': 'vulnerable', '5.9.1-1+deb11u3': 'vulnerable'}
  }),
  ('sid', {
    'isakmpd': {'20041012-10': 'vulnerable'},
    'libreswan': {'4.7-1': 'vulnerable'},
    'strongswan': {'5.9.8-3': 'vulnerable'}
  }),
  ])
def test_get_pkg_ver_status(get_html_page:str, release:str, expectation:str):
  '''
  Test parsing dom (security-tracker.debian.org) and return package versions 
  and vulnerables from the table
  '''
  dom = convert_html(get_html_page, 'dom')
  pkg_ver_status = get_pkg_ver_status(dom, release)
  for package in pkg_ver_status.keys():
    assert package in expectation.keys()
    for version in pkg_ver_status[package].keys():
      assert version in expectation[package].keys()
      assert pkg_ver_status[package][version] == expectation[package][version]


@pytest.mark.parametrize('version_1,version_2,expectation', [
  ('9', '3', True),
  ('10', '1', True),
  ('1.3.7', '1.10.2', False),
  ('3.27-6+deb10u2', '3.27-6+deb10u1', True),
  ('1:156.10~1+deb10u1', '1:156.3~1+deb10u1', True)
  ])
def test_version_comparison(version_1:str, version_2:str, expectation:str):
  '''
  Test package version comparison, 
  if first_ver > second_ver return True else False
  '''
  result = version_comparison(version_1, version_2)
  assert result == expectation


@pytest.mark.parametrize('package,release,expectation', [
  ('isakmpd', 'buster', ('20041012-8', 'vulnerable')),
  ('libreswan', 'buster', ('3.27-6+deb10u1', 'vulnerable')),
  ('strongswan', 'buster', ('5.7.2-1+deb10u3', 'vulnerable')),
  ('isakmpd', 'bullseye', ('not found', 'not found')),
  ('libreswan', 'bullseye', ('4.3-1+deb11u1', 'vulnerable')),
  ('strongswan', 'bullseye', ('5.9.1-1+deb11u3', 'vulnerable')),
  ('isakmpd', 'sid', ('20041012-10', 'vulnerable')),
  ('libreswan', 'sid', ('4.7-1', 'vulnerable')),
  ('strongswan', 'sid', ('5.9.8-3', 'vulnerable')),
  ])
def test_get_max_version_and_status(get_html_page:str, package:str, release:str, expectation:str):
  '''
  Test parsing dom (security-tracker.debian.org) and return max version and status
  '''
  dom = convert_html(get_html_page, 'dom')
  version, status = get_max_version_and_status(dom, package, release)
  assert version == expectation[0]
  assert status == expectation[1]