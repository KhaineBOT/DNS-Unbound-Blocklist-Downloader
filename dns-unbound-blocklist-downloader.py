import urllib2
import re
import argparse
import subprocess, shlex

#blocklist information

blocklists = {
	'abuse.ch Feodo Tracker (Domain)': {
		'id': 'abusefeododomain',
		'url':  'https://feodotracker.abuse.ch/blocklist/?download=domainblocklist',
		'regex' : '',
		'file' : 'feodo.domain',
	},
		'abuse.ch Zeus Tracker (Domain)': {
		'id': 'abusezeusdomain',
		'url':  'https://zeustracker.abuse.ch/blocklist.php?download=baddomains',
		'regex' : '',
		'file' : 'zeus.domain',
	},
	'abuse.ch Palevo Tracker (Domain)': {
		'id': 'abusepalevodomain',
		'url':  'https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist',
		'regex' : '',
		'file' : 'palevo.domain',
	},
	'malwaredomains.com Domain List': {
		'id': 'malwaredomainsdomain',
		'url': 'http://www.malwaredomainlist.com/hostslist/hosts.txt',
		'regex': '',
		'file' : 'malwaredomains.domain',
	},
	'PhishTank': {
		'id': 'phishtank',
		'url': 'http://data.phishtank.com/data/online-valid.csv',
		'regex': '/^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/',
		'file' : 'phishtank.domain',
	},
	'MVPS': {
		'id': 'mvps',
		'url': 'http://winhelp2002.mvps.org/hosts.txt',
		'regex': '',
		'file' : 'mvps.domain',
	},
	'pgl.yoyo.org': {
		'id': 'pgl.yoyo.org',
		'url': 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&mimetype=plaintext',
		'regex': '',
		'file' : 'pgl.yoyo.org.domain',
	},
	'Hosts File Project': {
		'id': 'hostsfileproject',
		'url': 'http://hostsfile.mine.nu/Hosts',
		'regex': '',
		'file' : 'hfp.domain',
	},
	'The Cameleon Project': {
		'id': 'cameleonproject',
		'url': 'http://sysctl.org/cameleon/hosts',
		'regex': '',
		'file' : 'cameleon.domain',
	},
	'AdAway mobile ads': {
		'id': 'adaway',
		'url': 'http://adaway.sufficientlysecure.org/hosts.txt',
		'regex': '',
		'file' : 'adaway.domain',
	},
	'hpHosts ad-tracking servers': {
		'id': 'hphosts',
		'url': 'http://hosts-file.net/download/hosts.txt',
		'regex': '',
		'file' : 'hphosts.domain',
	},
	'Someone Who Cares': {
		'id': 'someonewhocares',
		'url': 'http://someonewhocares.org/hosts/hosts',
		'regex': '',
		'file' : 'someonewhocares.domain',
	},
	'Ransomware': {
		'id': 'ransomware',
		'url': 'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt',
		'regex': '',
		'file' : 'ransomware.domain',
	}
}

def downloadAndProcessBlocklist(url, regex, filename):
	req = urllib2.Request(url)
	req.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)')

	contents = ''

	#download blocklist
	try:
		response = urllib2.urlopen(req)
		contents = response.read()
				
		#process blocklists
		if regex != '':
			match = re.findall(regex, contents)
			print match
			contents = match
	except urllib2.URLError as e:
		if hasattr(e, 'reason'):
			print 'We failed to reach a server.'
			print 'Reason: ', e.reason
		elif hasattr(e, 'code'):
			print 'The server couldn\'t fulfill the request.'
			print 'Error code: ', e.code
		else:
			print 'unknown error'

	return str(contents)
	

# main
IPV4_ADDR = '127.0.0.1'
IPV6_ADDR = '::1'

#sensible defaults
location = '/etc/unbound/'
filename = 'local-blocking-data.conf'
output = ""

parser = argparse.ArgumentParser(description='IP blocklist downloader and importer for pf and ip tables')
parser.add_argument('-l', '--blocklist_location',help='location to store blocklists', required=False)
parser.add_argument('-f', '--filename',help='filename of blocklist', required=False)
parser.add_argument('-n', '--blocklist_names',help='specify names of blocklists to download', required=False, type=lambda s: [str(item) for item in s.split(',')])

args = parser.parse_args()

if args.blocklist_location != None:
	location = args.blocklist_location

for key, value in sorted(blocklists.items()):

	#download all blocklists of the given type
	if args.blocklist_names == None:
		print('downloading '+key)
		output = output + downloadAndProcessBlocklist(value['url'], value['regex'], value['file'])
	else:
		#download specified blocklists
		if value['id'] in args.blocklist_names:
			print('downloading '+key)
			output = output + downloadAndProcessBlocklist(value['url'], value['regex'], value['file'])

#remove comments, duplicates and process
output = re.sub(r'(?m)^\#.*\n?', '', output)
listOutput = re.findall('(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', output)	
listOutput = list(set(listOutput))
listOutput = [x for x in listOutput if x != "127.0.0.1"]
listOutput = [x for x in listOutput if x != "s3-eu-west-1.amazonaws.com"]

#write to file
try:
	with open(location+filename, 'w') as f:
		
		for item in listOutput:
			
			f.write('local-data: \"')
			f.write("%s" % item)
			f.write(' A ' + IPV4_ADDR + '\"')
			f.write('\n')
			
			f.write('local-data: \"')
			f.write("%s" % item)
			f.write(' AAAA ' + IPV6_ADDR + '\"')
			f.write('\n')
			
		f.close()
except IOError as e:
	print e.reason
	
#reload unbound configuration
subprocess.check_call(shlex.split('/usr/sbin/service unbound restart'))
