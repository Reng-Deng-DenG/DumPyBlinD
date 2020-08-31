#coding:utf-8

sqlite = {
	'escape': ['\'', '"', ''],
	'comment': ['-- -', ''],
	'operator': ['AND'],
	'functionV': 'sqlite_version()=sqlite_version()',
	'functionT':'1=LIKE(1,UPPER(HEX(RANDOMBLOB({time}00000000/2))))'
}
