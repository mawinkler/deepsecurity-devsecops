#!/bin/bash

# call with ./report_parser.sh <report file>
cat $1 | egrep -o 'CVE-[0-9]+-[0-9]+' | egrep -o 'CVE-[0-9]+-[0-9]+' | sort | uniq | awk 'BEGIN{}{printf("%s ", $0)}END{}'
