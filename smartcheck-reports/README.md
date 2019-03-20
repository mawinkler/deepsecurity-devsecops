Reporting Scripts for Deep Security Smart Check

export DSSC_SERVICE="https://ip:port"

export DSSC_USERNAME"username"

export DSSC_PASSWORD="password"

export SCANID="dac3ccb2-a305-47d1-8749-b98d79bb3f29"

Generate cve cache file:

python nvdextractor.py

Generate report:

python screport.py
