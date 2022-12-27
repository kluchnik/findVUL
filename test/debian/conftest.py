# ----------------------
# import global modules
# ----------------------

import pytest
import os
import sys

# ----------------------
# import local modules
# ----------------------

MAIN_DIR_NAME = 'checkVDeb'

def get_dir(main_dir_name:str) -> str:
  ''' Возвращает основную директорию тестового окружения '''
  path_file = os.path.abspath(__file__)
  path_main = ''
  for item in path_file.split('/'):
    path_main += '{}/'.format(item)
    if item == main_dir_name:
      break
  return path_main

# Устанавливаем точку в основной директории тестового окружения
sys.path.insert(0, get_dir(MAIN_DIR_NAME))