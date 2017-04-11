'''
	########################################################################
		 	Script name:  IPReplookup.py
	   		       Type:  Python
   	   First date coded:  12/18/2016  
   	  Last date updated:  12/18/2016 
			 	Version:  0.1
		   	  	 Author:  Barny Steve Sanchez (barny.sanchez@us.ibm.com)
		   Collaborator:  Gabriela Picado Nunez (gabrielap@cr.ibm.com)

	 This script is part of Barny Sanchez's script repository. This 
	 was originally writen for very specific needs of the IBM MSS team, but 
	 it can be repurposed for any needs. 
	 If you modify this please give credit to the original work !
	 We offer no guarantees and assume no responsibilities for the
	 missuse of this code. Happy Hacking! 

	 Script explanation and purpose:
	 The IBM MSS team has the recurrent need of checking the IP reputation 
	 information during their investigations. This information may come from
	 different threat intelligence (TI) providers such as XForce Exchange (XFE).
	 Provided one or more IP addresses, this script leverages APIs to extract 
	 the information needed by the MSS team. As of this update, IPReplookup
	 uses only XFE's API but there plans to include more results from other
	 TI providers.

	 To run the script, simply execute it and help should display detailing 
	 the needed information. 

	########################################################################
'''


import requests,json,re,pyperclip,sys,time   
from requests.auth import HTTPBasicAuth

# The APIKEY / APIPASSWORD pair are unique to the user. IBM employees using IBM addresses 
# unlimited number of queries. Anybody else would have a 5,000 query/month limit unless the
# customer is using the commercial API

APIKEY 		= '77775b56-17c9-46a0-b5e2-bee3d7550641'
APIPASSWORD = '711a4008-759e-4705-91e5-3ae376b52e4e'

def cli_helpdoc():
	'''
	General help function, mainly text display, no actual actions taken
	'''
	help='''
 Steps to run:

 	1) Copy any IP or list of IP addresses to the clipboard (Ctrl-C).

 	2) Execute "IPReplookup.py"

 	3) The previous will provide results in a tabular format. If instead 
 	you want to print results in blocks, then execute the script specifying
 	block mode "IPReplookup.py --block"

 	If the previous doesn't help, make sure that the API key:password 
 	coded in the script are good. Try renewing these.

		'''
	print help

def XFEIPReputation(IPtosearch,printlist=True):
	'''
	XFEIPReputation connects to IBM's XFE API and makes 2 API calls for "IP Reputation" and 
	"WHOIS" data and combines the results. Information is displayed by default in a tabulated
	format (printlist=True) or in block mode (printlist=False).
	'''
	api_URL1 = 'https://api.xforce.ibmcloud.com/ipr/'+IPtosearch
	request = requests.get(api_URL1, auth=HTTPBasicAuth(APIKEY, APIPASSWORD))

	jsondata1 = json.loads(request.text)
	jsonoutput1= json.dumps(jsondata1, sort_keys=True, indent=4)

	api_URL2 = 'https://api.xforce.ibmcloud.com/whois/'+IPtosearch
	request = requests.get(api_URL2, auth=HTTPBasicAuth(APIKEY, APIPASSWORD))
	jsondata2 = json.loads(request.text)
	jsonoutput2= json.dumps(jsondata2, sort_keys=True, indent=4)

	apisource = 'XFE'
	notavailable = 'N/A'
	# The number of try/except clauses is because the data model in the documentation stated that 
	# many of the information needed is 'optional' which means that it may exist or not as part of 
	# the response. If it doesn't exist and I try to search for it's values, then the program can 
	# fail execution, and to the try/except clauses help me prevent that.
	try: risk = jsondata1['score']
	except: risk = notavailable
	try: 	
		categorization = jsondata1['cats']
		categorizationstring = ','.join('%s %d%%' % (key,int(val)) for (key,val) in categorization.items()) if len(categorization) >0 else notavailable
	except : categorizationstring = notavailable
	try: organization = jsondata2['contact'][0]['organization'] 
	except:	organization = notavailable
	try: country = jsondata2['contact'][0]['country']
	except : country = notavailable
	try: email = jsondata2['contactEmail']
	except : email = notavailable
	try: 
		updated = jsondata2['updatedDate']
		updated = list(re.search(r'(\d\d\d\d-\d\d-\d\d)',updated).groups(0))[0]
	except : updated = notavailable
	if printlist: 
		print '%-*s%-*s%-*s%-*s%-*s%-*s%-*s%-*s' %(16,IPtosearch,5,apisource,6,risk,38,categorizationstring,30,organization,24,country,28,email,15,updated)
	else:
		print 'IP:',IPtosearch
		print 'API Source:',apisource
		print 'Risk:',risk
		print 'Categorization:',categorizationstring
		print 'Organization:',organization
		print 'Country:',country
		print 'Email:',email
		print 'Last updated:',updated
		print ''

ListofIPs = pyperclip.paste()
ListofIPs = ListofIPs.encode("utf-8").split()

try:
	for IPaddress in ListofIPs:
		[0<=int(x)<256 for x in re.split('\.',re.match(r'^\d+\.\d+\.\d+\.\d+$',IPaddress).group(0))].count(True)==4
	badinput = False
except:
	badinput = True
	print '\n Something went wrong! Possibly what you have in the clipboard is not properly formated IP address information'

if len(ListofIPs) == 0 or (len(sys.argv) > 1 and sys.argv[1] != '--block') or badinput or (len(sys.argv) > 1 and sys.argv[1] == '--help'):
    cli_helpdoc()
else:
	try:	# unfortunately every IP has to be looked up individually. 
			# as of 12/18/2016, XFE's API does not allow bulk calls. The net result
			# is that for every IP address I must do 2 API calls which makes the whole
			# process slow and inefficient. 
		start_time = time.time()
		if len(sys.argv) > 1 and (sys.argv[1] == '--block'): 
			print ''
			for (count,IP) in enumerate(ListofIPs):
				XFEIPReputation(IP,printlist=False)
				total = count
		else:
			print ''
			print '%-*s%-*s%-*s%-*s%-*s%-*s%-*s%-*s' %(16,'IP',5,'API',6,'RISK',38,'CATEGORIZATION',30,'ORGANIZATION',24,'COUNTRY',28,'EMAIL',15,'UPDATED')
			print '{:=^157}'.format('=')
			for (count,IP) in enumerate(ListofIPs):
				XFEIPReputation(IP)
				total = count
			print '{:=^157}'.format('=')
		finish_time = time.time()
		print 'Total IP addresses looked up:',total+1,'(in %.2f seconds or %.2f seconds per IP lookup)'%((finish_time - start_time),(finish_time - start_time)/(total+1)),'\n'

	except:
		print '\n Something went wrong! Possibly what you have in the clipboard is not properly formated IP address information'
		cli_helpdoc()














 



'''
Testing set (copy-paste from this list if you'd like):
 
113.163.115.128
8.8.8.8
4.4.4.4
123.22.184.230
152.170.249.6
181.74.170.128
176.67.48.243
151.237.82.194
167.58.98.92
177.7.114.55
122.169.105.184
113.163.115.127 
199.199.199.199
209.59.118.133
202.181.184.162
113.163.115.128
75.130.229.21
203.106.96.229
182.180.157.23
178.251.110.83
125.120.191.80
119.153.109.164
41.82.1.62
114.134.190.184
121.201.3.231
124.105.55.189
193.251.186.147
211.227.170.106
219.76.176.111
201.206.66.106
178.72.153.252
47.23.162.134
82.94.238.115
86.109.170.70
222.186.161.72
202.86.174.90
69.14.210.16

'''















