#for j in 512 1k 2k 4k 8k 16k 32k 64k 128k 256k 512k
timestamp=$( date +%T )
mv results.txt results.txt.$timestamp 
for j in 64	128	192	256	320	384	448	512	576	640	704	768	832	896	960	1024	1088	1152	1216	1280	1344	1408	1472
	do
#		for i in 1 2 3 4 5 6 7 8 9 10  
#			do 
				sudo ip netns exec ns1 taskset -c 1 click tgen_sink.click size=$j
				click timestamp_parser.click size=$j > udpecho_$j.txt 2>&1
			 	python parser1.py $j >> results.txt	
#			done
	done
