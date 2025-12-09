#!/bin/bash
for file in 0*
do
	echo TEST $file
	node $file
	if [ $? -ne 0 ]
	then
		exit
	fi
done

for file in 1*
do
	echo TEST $file
	node $file
	if [ $? -ne 0 ]
	then
		exit
	fi
done
