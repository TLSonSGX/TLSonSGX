from __future__ import division
import csv
import sys

x1 = sys.argv[1]
file_name='udpecho_'+x1+'.txt'
#print file_name
mod_list = list(csv.reader(open(file_name, 'rb'), delimiter='|'))
sample_size=10000
x2="TLSonSGX"
dec_list=[]
for x in range (0, sample_size):
	y=int(mod_list[x][1],16)
	print x1 , y/1000000, x2
	#dec_list [x] = int(mod_list[x][1],16)

