''' vulnerability check on vulners.com website '''

import requests
import json
import time

try:
  from BeautifulSoup import BeautifulSoup
except ImportError:
  from bs4 import BeautifulSoup
from lxml import etree

def get_metadata_api_multi(api_key:str, cve:str) -> dict:
  ''' Get API vulners.com '''
  timeout = 60
  max_count = 5
  for item in range(max_count):
    metadata = get_metadata_api(api_key, cve)
    if metadata:
      break
    else:
      print('ERROR:', 'TIMEOUT VULNERS -', cve)
      time.sleep(timeout)
  return metadata

def get_metadata_api(api_key:str, cve:str) -> dict:
  ''' Get API vulners.com '''
  import vulners
  try:
    vulners_api = vulners.Vulners(api_key=api_key)
    return vulners_api.document(cve)
  except:
    return None

def str2dict(txt:str) -> dict:
  ''' Convert txt to dict '''
  try:
    return json.loads(txt)
  except:
    return {}

def get_cve(metadata:dict) -> str:
  try:
    return metadata['title']
  except:
    return 'not found'

def get_description(metadata:dict) -> str:
  try:
    return metadata['description']
  except:
    return 'not found'

def get_date_pub(metadata:dict) -> str:
  try:
    return metadata['published']
  except:
    return 'not found'

def get_cvss2_access_vector(metadata:dict) -> str:
  try:
    return metadata['cvss2']['cvssV2']['accessVector']
  except:
    return 'not found'

def get_cvss2_score(metadata:dict) -> str:
  try:
    return str(metadata['cvss2']['cvssV2']['baseScore'])
  except:
    return 'not found'

def get_cvss3_attack_vector(metadata:dict) -> str:
  try:
    return metadata['cvss3']['cvssV3']['attackVector']
  except:
    return 'not found'

def get_cvss3_score(metadata:dict) -> str:
  try:
    return str(metadata['cvss3']['cvssV3']['baseScore'])
  except:
    return 'not found'

def get_status_nessus(metadata:dict) -> str:
  try:
    refs = metadata['enchantments']['dependencies']['references']
  except:
    refs = []
  for ref in refs:
    if 'type' in ref.keys() and ref['type'] == 'nessus':
      return 'yes'
  return 'no'

def get_cve_info(api_key:str, distr:str, release:str, cve:str) -> dict:
  ''' Returns vulnerability data by CVE (vulners.com) '''
  get_id = '{}CVE:{}'.format(distr.upper(), cve)
  url = 'https://vulners.com/api/v3/search/id/?id={}'.format(get_id)
  url_web = 'https://vulners.com/debiancve/{}CVE:{}'.format(distr.upper(), cve)
  metadata = get_metadata_api(api_key, cve)
  if metadata:
    return {
      'cve': cve,
      'description': get_description(metadata),
      'href_api': url,
      'href_web': url_web,
      'date_published': get_date_pub(metadata),
      'cvss2_score': get_cvss2_score(metadata),
      'cvss2_access_vector': get_cvss2_access_vector(metadata),
      'cvss3_score': get_cvss3_score(metadata),
      'cvss3_attack_vector': get_cvss3_attack_vector(metadata),
      'status_vulners': 'yes',
      'status_nessus': get_status_nessus(metadata)
    }
  else:
    return {
      'cve': cve,
      'description': 'N/A',
      'href_api': url,
      'href_web': url_web,
      'date_published': 'N/A',
      'cvss2_score': 'N/A',
      'cvss2_access_vector': 'N/A',
      'cvss3_score': 'N/A',
      'cvss3_attack_vector': 'N/A',
      'status_vulners': 'no',
      'status_nessus': 'N/A'
    }
