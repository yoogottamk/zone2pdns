.PHONY: test

test:
	echo p | python zone2pdns.py example.com examples/example.com.zone | diff -d - examples/example.com.payload.json
