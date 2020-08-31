#coding:utf-8
import requests
from colorama import *
from time import *
init()

def Fuzz(setting, payload):

	sqli_type = setting['sqli_type']
	method = setting['method']
	url = setting['url']
	delay = int(setting['delay'])
	timeout = setting['timeout']
	msg = setting['msg']

	data = setting['postData']
	headers = setting['headers']

	tofind = setting['tofind']
	p_time = int(setting['p_time'])

	timeout = setting['timeout']
	headers = setting['headers']

	vuln = False


	# Inject payload

	if method == 'GET':
		url = url.replace('{fuzz}', payload)

	elif method == 'POST':

		for key, value in data.items():
			if '{fuzz}' in value:
				data[key] = data[key].replace('{fuzz}', payload)

	elif method == 'HEAD':

		for key, value in headers.items():
			if '{fuzz}' in value:
				headers[key] = headers[key].replace('{fuzz}', payload)

	# Make delay if needed

	if delay != 0:
		sleep(delay)

	# Make HTTP Request

	try:

		if method == 'GET' or method == 'HEAD':
			r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)

		else:
			r = requests.post(url, data=data, headers=headers, timeout=timeout, allow_redirects=False)

	
	# Catch Error

	except requests.exceptions.RequestException as e:
		print('Error: {}'.format(e))
	except requests.exceptions.HTTPError as e:
		print('HTTP Error {}'.format(e))
	except requests.exceptions.ConnectionError as e:
		print('Connection Error {}'.format(e))
	except requests.exceptions.Timeout as e:
		print('Timeout Error: {}'.format(e))


	# Get Response

	code = str(r.status_code)
	page_source = str(r.text)
	time = int(r.elapsed.total_seconds())

	# Check Vulnerability

	if sqli_type == 'BSQLI':
		if tofind in page_source:
			vuln = True

	else:
		if time >= p_time:
			vuln = True

	# Display message 

	if msg == 'y':
		if vuln == True:
			print(method+'/ '+Fore.YELLOW+payload+Fore.RESET+'\t\tHTTP '+code+Fore.GREEN+' y'+Fore.RESET)
		else:
			print(method+'/ '+Fore.YELLOW+payload+Fore.RESET+'\t\tHTTP '+code+Fore.RED+' n'+Fore.RESET)

	# Reset payload

	if method == 'GET':
		url = url.replace(payload, '{fuzz}')

	elif method == 'POST':

		for key, value in data.items():
			if payload in value:
				data[key] = data[key].replace(payload, '{fuzz}')

	elif method == 'HEAD':
		for key, value in headers.items():
			if payload in value:
				headers[key] = headers[key].replace(payload, '{fuzz}')


	return vuln

