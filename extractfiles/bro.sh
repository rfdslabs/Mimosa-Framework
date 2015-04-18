#!/bin/bash
for i in *.pcap
do
 bro -r ${i} extrac.bro
done
