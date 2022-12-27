import json
import csv

def open_f(path:str, encode:str='utf-8') -> str:
  ''' open file '''
  try:
    f = open(path, 'r', encoding=encode)
    output = f.read()
    f.close()
    return output
  except:
    return None

def save_f(path:str, data:str, encode:str='utf-8') -> bool:
  ''' save data to file '''
  try:
    with open(path, 'w', encoding=encode) as f:
      f.write(data)
    return True
  except:
    return False

def add_f(path:str, data:str, encode:str='utf-8') -> bool:
  ''' add data to file '''
  try:
    with open(path, 'a', encoding=encode) as f:
      f.write(data)
    return True
  except:
    return False

def open_json(path:str, encode:str='utf-8') -> dict:
  ''' open file json format '''
  try:
    with open(path, 'r', encoding=encode) as f:
      output = json.load(f)
    return output
  except:
    return None

def save_json(path:str, data:dict, encode:str='utf-8') -> bool:
  ''' save data to json file '''
  try:
    with open(path, 'w', encoding=encode) as f:
      json.dump(data, f, ensure_ascii=False, indent=2)
    return True
  except:
    return False

def save_csv(path:str, header:list, data:list, dialect:str=';', encode:str='utf-8') -> bool:
  ''' save data to csv file '''
  try:
    csv.register_dialect("SEPARATOR", delimiter=dialect)
    with open(path, 'w', encoding=encode, newline='') as f:
      writer = csv.writer(f, dialect="SEPARATOR")
      writer.writerow(header)
      writer.writerows(data)
    return True
  except:
    return False

