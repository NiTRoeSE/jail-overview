#!/usr/bin/env python
import subprocess
#from collections import namedtuple
from tabulate import tabulate

# create emtpy arrays
jailname = []
currentfailed = []
totalfailed =[] 
currentlybanned =[]
totalbanned = []
bannediplist = []
bannediplistperjail =[]
    
#with open("./jails.txt") as jails:
#    content = jails.read()
#    jaillist = content.split()
#    jails.close()

jaillist = subprocess.check_output('fail2ban-client status', shell=True)
jaillist = jaillist.replace(',','') #remove "," from output
jaillist = jaillist.split() #seperate output to list elements
jaillist = jaillist[9:] # drop first 9 elements
#print(jaillist)
#exit(0)    

#check if system is centos and uses systemd logging for sshd
os = subprocess.check_output('cat /proc/version', shell=True)


for jail in jaillist:


   jailcontent = subprocess.check_output('fail2ban-client status {}'.format(jail), shell=True)
   #jailcontent = os.popen('fail2ban-client status {}'.format(jail)).read()	   
   #jailcontent = os.system('fail2ban-client status {}'.format(jail))
   jailcontent = jailcontent.split()
   #print(jailcontent)
   if jail == 'sshd' and 'centos' in os:
      jailname.append(jailcontent[4])
      currentfailed.append(jailcontent[11])
      totalfailed.append(jailcontent[16])
      currentlybanned.append(jailcontent[29])
      totalbanned.append(jailcontent[33])
      #check if last element is empty or is "list" otherwise blocked ips are given
     # lets get the list of ips if ips are present
      if jailcontent[-1] != 'None' and jailcontent[-1] != 'list:': #if last element in array not ..
         count = len(jailcontent) #get number of entries in array

         for i in range(36, count): #loop from element 36 ( first ip if they are present) to last element of array
            bannediplistperjail.append(jailcontent[i])

         bannediplist.append(bannediplistperjail) #array in array because in bannediplist can be multiple ips..
      else:
         bannediplist.append('')
       	 #print (bannediplist)

   elif("apache" in jail):
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
       	 #print (bannediplist)
   else:
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
         #print (bannediplist)    
   
   #print (jailcontent[4]) #jail-name
   #print (jailcontent[11]) #currently-failed
   #print (jailcontent[16]) #total failed
   #print (jailcontent[27]) #currently banned
   #print (jailcontent[31]) #total banned
   #print (jailcontent[36]) #ip list if banned ips are present

#print(bannediplist)

headers = ['Jail', 'Current Failed', 'Total Failed', 'Current Banned', 'Total Banned', 'Banned Ips'] 
table = zip(jailname, currentfailed, totalfailed , currentlybanned, totalbanned, bannediplist)
#print(table)
x = (tabulate(table, headers=headers,tablefmt="fancy_grid"))
print (x)
