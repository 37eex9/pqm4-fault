#!/usr/bin/env bash

# simple script to preparse .sage files and make them work as python scripts

for i in threshold BIKE_params
do
	sage --preparse $i.sage
	mv $i.sage.py $i.py
	chmod u+x $i.py
done