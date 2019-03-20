#!/bin/bash

# call with ./cveextractor.sh <report file>
cat $1 | egrep -o 'CVE-[0-9]+-[0-9]+' | sort | uniq | awk 'BEGIN{printf("[")}{printf("%s, ", $0)}END{printf("]")}'
echo
