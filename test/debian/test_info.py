''' Test lib/debian/info.py '''

import pytest
from lxml import etree

import lib.file
from lib.debian.info import convert_html
from lib.debian.info import get_package_source
from lib.debian.info import get_package_desc
from lib.debian.info import get_package_fdesc

@pytest.fixture
def get_html_page(scope="module") -> str:
  ''' Open and return http page '''
  FILE_HTML_PAGE = 'test/debian/example_info.html'
  html = lib.file.open_f(FILE_HTML_PAGE)
  yield html

def test_open_html_page(get_html_page:str):
  ''' Open file html page '''
  assert get_html_page != None

def test_html_to_dom(get_html_page:str):
  ''' Convert html txt to dom object '''
  dom = convert_html(get_html_page, 'dom')
  assert type(dom) is etree._Element

def test_get_package_source(get_html_page:str):
  ''' Test parsing dom (packages.debian.org) and return package source '''
  dom = convert_html(get_html_page, 'dom')
  source_package = get_package_source(dom)
  expectation = 'expat'
  assert source_package == expectation

def test_get_package_desc(get_html_page:str):
  ''' Test parsing dom (packages.debian.org) and return package description '''
  dom = convert_html(get_html_page, 'dom')
  description = get_package_desc(dom)
  expectation = 'XML parsing C library - runtime library'
  assert description == expectation

def test_get_package_fdesc(get_html_page:str):
  ''' Test parsing dom (packages.debian.org) and return package full description '''
  dom = convert_html(get_html_page, 'dom')
  full_description = get_package_fdesc(dom)
  expectation = 'This package contains the runtime, \
shared library of expat, the C library for parsing XML. \
Expat is a stream-oriented parser in which an application \
registers handlers for things the parser might find in the \
XML document (like start tags).'
  assert full_description == expectation