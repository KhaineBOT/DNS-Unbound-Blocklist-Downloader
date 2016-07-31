import urllib2
import re
import argparse
import subprocess, shlex

#blocklist information

blocklists = {
	'abuse.ch Feodo Tracker (Domain)': {
		'id': 'abusefeododomain',
		'url':	'https://feodotracker.abuse.ch/blocklist/?download=domainblocklist',
		'regex' : '',
		'file' : 'feodo.domain',
	},
		'abuse.ch Zeus Tracker (Domain)': {
		'id': 'abusezeusdomain',
		'url':	'https://zeustracker.abuse.ch/blocklist.php?download=baddomains',
		'regex' : '',
		'file' : 'zeus.domain',
	},
	'abuse.ch Palevo Tracker (Domain)': {
		'id': 'abusepalevodomain',
		'url':	'https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist',
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
	},
	#https://github.com/pi-hole/pi-hole/blob/master/adlists.default
	'pi-hole': {
		'id': 'pi-hole',
		'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
		'regex': '',
		'file' : 'pi-hole.domain',
	},
	'adblock': {
			'id': 'adblock',
			'url': 'http://adblock.gjtech.net/?format=unix-hosts',
			'regex': '',
			'file' : 'adblock.domain',
		},
	'disconnect-ad': {
			'id': 'disconnect-ad',
			'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt',
			'regex': '',
			'file' : 'disconnect-ad.domain',
		},	
	'disconnect-tracking': {
			'id': 'disconnect-tracking',
			'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt',
			'regex': '',
			'file' : 'disconnect-tracking.domain',
		},
	'Quidsups tracker list': {
			'id': 'quidsup',
			'url': 'https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt',
			'regex': '',
			'file' : 'quidsup.domain',
		},
	'Windows 10 telemetry list': {
		'id': 'wintelemetry',
		'url': 'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/win10/spy.txt',
		'regex': '',
		'file' : 'wintelemetry.domain',
		},
	'notracking': {
		'id': 'notracking',
		'url': 'https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt',
		'regex': '',
		'file' : 'notracking.domain',
		}						
}

def is_valid_hostname(hostname):        
	if hostname.endswith("."): # A single trailing dot is legal
		hostname = hostname[:-1]	
	if len(hostname) > 253:
		return False
	# must be not all-numeric, so that it can't be confused with an ip-address
	if re.match(r"[\d.]+$", hostname):
		return False

	allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
	return all(allowed.match(x) for x in hostname.split("."))

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

#remove comments, duplicates, bad data and process
output = re.sub('127.0.0.1', '', output)

listOutput = output.split('\n')

listOutput = [x for x in listOutput if '#' not in x]
listOutput = [x for x in listOutput if ']' not in x]
listOutput = [x for x in listOutput if '[' not in x]
listOutput = [x for x in listOutput if ',' not in x]

listOutput = map(str.strip, listOutput)

#remove whitelist
listOutput = [x for x in listOutput if x != "127.0.0.1"]
listOutput = [x for x in listOutput if x != "::1"]
listOutput = [x for x in listOutput if x != "localhost"]
listOutput = [x for x in listOutput if x != "s3-eu-west-1.amazonaws.com"]

#removes blank lines
listOutput = filter(None, listOutput)

#remove duplicates
listOutput = list(set(listOutput))

#allows only valid hostnames
listOutput = filter(is_valid_hostname, listOutput)

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
subprocess.check_call(shlex.split('/usr/sbin/service local_unbound restart'))
