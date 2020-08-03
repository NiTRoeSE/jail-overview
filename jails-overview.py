#!/usr/bin/env python

'''
--- Jails Overview ---
This script gives a compact overview about your fail2ban jails, espacially if you have a lot of jails.
This script is tested on Centos7 and Ubuntu 18.04.
Its possible that the output of fail2ban slightly varies between linux distributions and thevscript fail.


'''


import subprocess
from tabulate import tabulate

# create emtpy arrays
jailname = []
currentfailed = []
totalfailed =[] 
currentlybanned =[]
totalbanned = []
bannediplist = []
bannediplistperjail =[]
    
# get aktive jails
jaillist = subprocess.check_output('fail2ban-client status', shell=True)
jaillist = jaillist.replace(',','') #remove "," from output
jaillist = jaillist.split() #seperate output to list elements
jaillist = jaillist[9:] # drop first 9 elements


#check if system is centos and uses journal logging for sshd (longer output)
os = subprocess.check_output('cat /proc/version', shell=True)


for jail in jaillist:


   jailcontent = subprocess.check_output('fail2ban-client status {}'.format(jail), shell=True)
   jailcontent = jailcontent.split()
   
   if jail == 'sshd' and 'centos' in os:
      jailname.append(jailcontent[4])
      currentfailed.append(jailcontent[11])
      totalfailed.append(jailcontent[16])
      currentlybanned.append(jailcontent[29])
      totalbanned.append(jailcontent[33])
      #check if last element is empty or is "list" otherwise blocked ips are given
      #lets get the list of ips if ips are present
      if jailcontent[-1] != 'None' and jailcontent[-1] != 'list:': #if last element in array not ..
         count = len(jailcontent)   #get number of entries in array
         for i in range(36, count): #loop from element 36 ( first ip if they are present) to last element of array
            bannediplistperjail.append(jailcontent[i])
         bannediplist.append(bannediplistperjail) #array in array because in bannediplist can be multiple ips..
      else:
         bannediplist.append('')
       	

   elif("apache" in jail): # longer output because of 2 logfiles
      jailname.append(jailcontent[4])
      currentfailed.append(jailcontent[11])
      totalfailed.append(jailcontent[16])
      currentlybanned.append(jailcontent[28])
      totalbanned.append(jailcontent[32])
      
      if jailcontent[-1] != 'None' and jailcontent[-1] != 'list:':
         count = len(jailcontent)
         for i in range(37, count):
            bannediplistperjail.append(jailcontent[i])
         bannediplist.append(bannediplistperjail)
      else:
         bannediplist.append('')
       	 
   else: # standard output (1 logfile)
      jailname.append(jailcontent[4])
      currentfailed.append(jailcontent[11])
      totalfailed.append(jailcontent[16])
      currentlybanned.append(jailcontent[27])
      totalbanned.append(jailcontent[31])
      
      if jailcontent[-1] != 'None' and jailcontent[-1] != 'list:':
         count = len(jailcontent) 
         for i in range(36, count):
            bannediplistperjail.append(jailcontent[i])
         bannediplist.append(bannediplistperjail)
      else:
         bannediplist.append('')
        
# create table
headers = ['Jail', 'Current Failed', 'Total Failed', 'Current Banned', 'Total Banned', 'Banned Ips'] 
table = zip(jailname, currentfailed, totalfailed , currentlybanned, totalbanned, bannediplist)
x = (tabulate(table, headers=headers,tablefmt="fancy_grid"))
print (x)
