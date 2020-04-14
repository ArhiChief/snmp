# SMART-SNMP
`smart-snmp` is a lightweight program written on C and used as SNMP server. Main feature of `smart-snmp` is possibility
to get or set values on demand by providing callbacks for small shell or Lua scripts.

## Installation
TBD

## Usage
```shell script
smart-snmp [options]
    -4, --use-ipv4     
      Use IPv4, default
    -6, --use-ipv6
      Use IPv6
    -a, --auth
      Require client authentication, thus SNMP version 2c, default is off.
    -c, --community
      SNMP version 2c authentication, or community, string, default is "public". 
      Remeber to also enable --auth to activate authentication.
    -h, --help
      Show summary of command line options and exit.
    -m, --max-connections NUMBER
      Amount of connections concurently handled by program, default is 10.
    -p, --udp-port PORT
      UDP port to listen to for incoming connections, default is 161.
    -P, --tcp-port PORT
      TCP port to listen to for incoming connections, default is 161.
    -s, --syslog
      Use syslog for logging
    -v, --version
      Show program version and exit.
```

### Request handlers
`smart-snmp` can handle some requests himself, see [OIDs supported by default](#oids-supported-by-default). Other should 
be handled manually, otherwise `noSuchName` PDU will be returned. To manage custom OIDs `smart-snmp` provides special
callbacks what can be processed by shell and/or Lua scripts. Before starting listening for incoming requests `smart-snmp`
scan directory with scripts and add store references to them in internal MIB database. If during scan process `smart-snmp`
find multiple handlers for same OID it will stop with error and tell files what are wrong. Lua scripts are checked for 
correctness. `smart-snmp` stores only paths to scripts and call them if appropriate request will come.

`smart-snmp` if started in `tcp` mode can handle up to `max-connections` connections concurrently. In this case, to 
prevent race conditions all requests to the same OIDs are passed through read-write locks. This means concurrent read 
access and exclusive write access.
  
#### Lua scripts
TBD
#### Shell scripts
Shell script will be called in this way:
```shell script
</path/to/script> method [argument]
```
Possible methods are:
- **oid** - ask script to return OID what will be handled by this script. This method will be called once during `smart-smpt` start;
- **type** - ask script to return type of OID. This method will be called once during `smart-smpt` start Possible types are:
    - **INTEGER** - return value is integer value;
    - **STRING** - return type is string;
    - **OID** - return type is OID;
- **get** - ask script to return actual value for OID. Script should return string value what will be converted by 
`smart-snmp` to type returned by **type** method call.
- **set** - ask script to update value for OID with value passed in *argument*.
    
Simple shell script can look like this:
```shell script
#!/bin/bash
# 
# smart-snmp callback script to handle 1.3.6.1.2.1.1.1 (Device Model)
#

get_oid () {
  echo -n "1.3.6.1.2.1.1.1"
}

get_type () {
  echo -n "STRING"
}

get_val () {
  echo -n "MySimpleDevice"
}

set_val () {
  local val = $3 # passed string value will be here
  exit 4; # 4 means readOnly 
}

case "$1" in
  oid)
    get_oid
  ;;
  type)
    get_type
  ;;
  get)
    get_val
  ;;
  set)
    set_val
  ;;
  *)
    exit -1;
  ;;
esac

exit 0 # 0 means noError 
```

#### OIDs supported by default
TDB

### Running as daemon
By default, `smart-snmp` is not applicable to run as daemon. Use separate wrapper like `start-stop-daemon` from **BusyBox**
or other tools.