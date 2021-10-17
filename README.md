# `zone2pdns`

Like `pdnsutil load-zone` but better.
 - preserves comments from zonefile
 - adds commented records as disabled records on pdns

## Usage
### Preprocessing
You need to make some changes to the zone file in order for this parser to work

1. collapse SOA record into a single line (or remove all comments within the SOA record parenthesis)
2. add "owner" to all fields

e.g.:
wouldn't work, parser doesn't handle this right now
```
services  A     10.0.1.10
          AAAA  aaaa:bbbb::10
          A     10.0.1.11
          AAAA  aaaa:bbbb::11
```

will work
```
services  A     10.0.1.10
services  AAAA  aaaa:bbbb::10
services  A     10.0.1.11
services  AAAA  aaaa:bbbb::11
```

A sample has been provided in examples.

### Generating payload
Usage:
```
python zone2pdns.py ZONE path/to/zonefile
```

Example:
```
python zone2pdns.py example.com examples/example.com.zone
```

To just view the json, type `p`.
Type anything else to quit.

### Adding records to pdns
set these env variables:
1. `PDNS_API_HOST`: (defaults to `localhost:8081`)
2. `PDNS_SERVER`: the server to which this zone will be added (most probably `localhost`, defaults to `localhost`. verify by `GET /api/v1/servers `)
3. `PDNS_API_KEY`: powerdns api key, no default

```
PDNS_API_KEY=api_key python zone2pdns.py example.com examples/example.com.zone
```

Type `y` to send `PATCH /api/v1/servers/{server}/zone/{ZONE}` and add records to pdns

## References
1. The `zoneparser` is from https://github.com/GertBurger/zoneparser. It has been modified to parse comments in records and a few other modifications to make this work.
