'''
Выполнение удаленных команд по ssh

Для работы необходимо установить paramiko: pip3 install paramiko

Пример использования:

>>> import lib.ssh
>>> pc = lib.ssh.UNION()
>>> ssh_cfg = {
... 'ip': '10.0.4.213',
... 'port': 22,
... 'username': 'user',
... 'password': '12345678'
... }
>>> pc.set_connParam(**ssh_cfg)
True
>>> pc.connect()
True

>>> cmd = \'''
... whoami
... ls /var/
... echo 'test msg 1'
... echo
... run_not_cmd
... echo 'test msg 2'
... \'''

>>> pc.run_command(cmd)
True

>>> pc.get_line_std('stdin')
('', 'whoami', 'ls /var/', "echo 'test msg 1'", 'echo', 'run_not_cmd', 
"echo 'test msg 2'", '')

>>> pc.get_line_std('stdout')
('user', 'backups', 'cache', 'lib', 'local', 'lock', 'log', 'mail', 
'opt', 'run', 'spool', 'tmp', 'test msg 1', '', 'test msg 2', '')

>>> pc.get_line_std('stderr')
('bash: line 5: run_not_cmd: command not found', '')

>>> cmd = \'''
... whoami
... ls /var/
... echo 'test msg 1'
... echo
... run_not_cmd
... echo 'test msg 2'
... \'''

>>> pc.run_command_match(cmd)
True

>>> len_cmd = len(pc.get_line_std('stdin'))
>>> for item in range(0, len_cmd-1):
...   print('> item:', item)
...   print('stdin: ', pc.get_line_std('stdin')[item])
...   print('stdout:', pc.get_line_std('stdout')[item])
...   print('stderr:', pc.get_line_std('stderr')[item])

> item: 0
stdin:
stdout: ('',)
stderr: ('',)
> item: 1
stdin:  whoami
stdout: ('user', '')
stderr: ('',)
> item: 2
stdin:  ls /var/
stdout: ('backups', 'cache', 'lib', 'local', 'lock', 'log', 'mail', 'opt', 'run', 'spool', 'tmp', '')
stderr: ('',)
> item: 3
stdin:  echo 'test msg 1'
stdout: ('test msg 1', '')
stderr: ('',)
> item: 4
stdin:  echo
stdout: ('', '')
stderr: ('',)
> item: 5
stdin:  run_not_cmd
stdout: ('',)
stderr: ('bash: run_not_cmd: command not found', '')
> item: 6
stdin:  echo 'test msg 2'
stdout: ('test msg 2', '')
stderr: ('',)

>>> pc.disconnect()
True
'''

import paramiko

class UNION():
  ''' Удаленое выполнение ssh команд'''
  def __init__(self):
    self.__ssh = paramiko.SSHClient()
    self.__connect = {
      'ip': '127.0.0.1',
      'port': '22',
      'username': 'user',
      'password': '12345678'}
    self.__line_stdin = ()
    self.__line_stdout = ()
    self.__line_stderr = ()
    self.__type_command = None

  def set_ip(self, ip:str) -> None:
    ''' Задать ip '''
    self.__connect['ip'] = ip

  def set_port(self, port:str) -> None:
    ''' Задать порт '''
    self.__connect['port'] = port

  def set_password(self, password:str) -> None:
    ''' Задать пароль '''
    self.__connect['password'] = password

  def set_username(self, username:str) -> None:
    ''' Задать пароль '''
    self.__connect['username'] = username

  def set_connParam(self, **kwarg) -> None:
    '''
    Задать новое значение параметрам:
    example-1: <class>.set_parameters(ip='192.168.1.11', login='root', password='12345678')
    example-2: <class>.set_parameters(**{'ip':'192.168.1.11', 'login':'root', 'password':'12345678'})
    '''
    status = False
    try:
      for item in kwarg.keys():
        self.__connect[item] = kwarg[item]
      status = True
    except Exception as exc:
      stderr = 'ERROR: failed set connect parameters:\n{}'.format(exc)
      self.set_line_std('stderr', stderr)
      status = False
    return status

  def get_connParam(self) -> dict:
    ''' Вернуть параметры соединения '''
    return self.__connect
    
  def get_sConnParam(self, select:str) -> str:
    ''' Вернуть выбранный параметр соединения
    in:
        select: ['ip'|'port'|'username'|'password']
    '''
    if select == 'ip':
      connParam = self.__parameters['ip']
    elif select == 'port':
      connParam = self.__parameters['port']
    elif select == 'username':
      connParam = self.__parameters['username']
    elif select == 'password':
      connParam = self.__parameters['password']
    else:
      connParam = ''
    return connParam

  def get_line_std(self, select:str='stdout') -> tuple:
    ''' Вернуть ввод std
    in:
        select: ['stdin'|'stdout'|'stderr']
    '''
    if select == 'stdin':
      return self.__line_stdin
    elif select == 'stdout':
      return self.__line_stdout
    elif select == 'stderr':
      return self.__line_stderr
    else:
      return ()

  def connect(self) -> bool:
    ''' Соединение по ssh '''
    try:
      self.__ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      self.__ssh.connect(self.__connect['ip'],
        port=self.__connect['port'],
        username=self.__connect['username'], 
        password=self.__connect['password'])
      return True
    except Exception as exc:
      stderr = 'ERROR: failed to connect via ssh:\n{}'.format(exc)
      self.set_line_std('stderr', stderr)
      return False

  def disconnect(self) -> bool:
    ''' Разрыв соединения по ssh '''
    if self.__ssh:
      self.__ssh.close()
    return True

  def set_line_std(self, select:str, std:str, fdecode:str='utf8') -> None:
    ''' Задать значение ssh вывода
    in:
        select: ['stdin'|'stdout'|'stderr']
        std: str
    '''
    if isinstance(std, bytes):
      std_list = std.decode(fdecode).split('\n')
    elif isinstance(std, str):
      std_list = std.split('\n')
    else:
      std_list = ('ERROR: format not defined',)
    # set std -> stdin | stdout | stderr
    if select == 'stdin':
      self.__line_stdin = tuple(std_list)
    elif select == 'stdout':
      self.__line_stdout = tuple(std_list)
    elif select == 'stderr':
      self.__line_stderr = tuple(std_list)

  def run_command(self, cmd:str) -> bool:
    ''' Выполнение команд по ssh '''
    status = False
    try:
      _, ssh_stdout, ssh_stderr = self.__ssh.exec_command(str(cmd))
      stdin = cmd
      stdout = ssh_stdout.read()
      stderr = ssh_stderr.read()
      status = True
    except Exception as exc:
      stdin = cmd
      stdout = ''
      stderr = 'ERROR: commands cannot be executed:\n{}'.format(exc)
      status = False
    self.set_line_std('stdin', stdin)
    self.set_line_std('stdout', stdout)
    self.set_line_std('stderr', stderr)
    return status

  def run_command_daemon(self, cmd:str) -> bool:
    ''' Выполнение команды без вывода в режиме демона '''
    status = False
    try:
      _, _, _ = self.__ssh.exec_command(cmd)
      status = True
    except Exception as exc:
      stdin = cmd
      stdout = ''
      stderr = 'ERROR: commands cannot be executed:\n{}'.format(exc)
      self.set_line_std('stdin', stdin)
      self.set_line_std('stdout', stdout)
      self.set_line_std('stderr', stderr)
      status = False
    return status

  def run_command_match(self, cmd:str, fdecode:str='utf8') -> bool:
    ''' Выполнение команд по ssh с сопостовлением stdin stdout stderr '''
    status = True
    # check cmd
    try:
      cmd_line = str(cmd).split('\n')
      status &= True
    except:
      stdin = cmd
      stdout = ''
      stderr = 'ERROR: commands cannot be executed:\n{}'.format(exc)
      self.set_line_std('stdin', cmd)
      self.set_line_std('stdout', stdout)
      self.set_line_std('stderr', stderr)
      status &= False
    # for cmd
    if status:
      self.__line_stdin = ()
      self.__line_stdout = ()
      self.__line_stderr = ()
      for cmd_item in cmd_line:
        stdin = cmd_item
        try:
          _, ssh_stdout, ssh_stderr = self.__ssh.exec_command(cmd_item)
          stdout = ssh_stdout.read().decode(fdecode).split('\n')
          stderr = ssh_stderr.read().decode(fdecode).split('\n')
          status &= True
        except Exception as exc:
          stdout = ('', )
          stderr = ('ERROR:\n{}'.format(exc), )
          status &= False
        self.__line_stdin += (stdin, )
        self.__line_stdout += (tuple(stdout), )
        self.__line_stderr += (tuple(stderr), )
    return status