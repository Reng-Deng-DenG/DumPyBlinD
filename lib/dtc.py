#coding:utf-8
from lib.req import *

def detect(setting, dict, dbms):

	if dbms == 'SQLite':
		time = '9'
	else:
		time = setting['p_time']
		
	sqli_type = setting['sqli_type']

	vuln = False

	if sqli_type == 'BSQLI':

		for e in dict['escape']:
			if vuln:
				break
			for c in dict['comment']:
				if vuln:
					break
				for o in dict['operator']:
					if vuln:
						break
					
					payload = ' ' + e + ' ' + o + ' ' + dict['functionV'] + c

					if Fuzz(setting, payload):
						setting['escape'] = e
						setting['comment'] = c
						setting['operator'] = o
						setting['dbms'] = dbms
						vuln = True
						break

					else:
						continue
					

	else:

		for e in dict['escape']:
			if vuln:
				break
			for c in dict['comment']:
				if vuln:
					break
				for o in dict['operator']:

					dict['functionT'] =  dict['functionT'].replace('{time}', time)
					payload = ' ' + e + ' '+ o + ' '+ dict['functionT'] + c

					if Fuzz(setting, payload):
						setting['escape'] = e
						setting['comment'] = c
						setting['operator'] = o
						setting['dbms'] = dbms
						vuln = True
						break

					else:
						continue
	return vuln
