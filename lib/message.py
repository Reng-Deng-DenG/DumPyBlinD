#coding:utf-8

legalDisclaimer = '[!] Legal disclaimer : This tool are for educational and research purposes only'


def clear():
	print(chr(27) + chr(91) + 'H' + chr(27) + chr(91) + 'J');

def Question(message):

	do = False
	question = input(message)

	if question == 'Y' or question == 'y':
		do = True

	return do
