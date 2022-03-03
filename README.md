BlueCoat2UserGate
=================
## What?
### This program is a parser, converter and uploader combined
### Coverage is partial. Based on my specific use case
### Input:
- Text file containing BlueCoat proxy rules
- Rule category (specific to my use case,
	basicaly for changing behavior between
	two rule sets if needed)
- Environment paramters such as:
  - Username <== FW_USERNAME
  - Password <== FW_PASSWORD
  - RPC URL <== RPC_URL (for UserGate) in form of http://\<address\>:4040/rpc
  - UserGate Management Center address <== FW_ADDRESS (for UserGate Management Center upload case)
		in form of IP or domain name
  - LDAP server name <== LDAP_SERVER_NAME (as added to the configuration of UserGate)
  - UserGate prefix <== FW_PREFIX (for UserGate Management Center case)
### Output:
Parsed rules that are combined based either on equal source parameters
	or equal destination parameters

Applied to UserGate or UserGate Management Center based on which extractor function is used
## Why?
Used in pilot project. I made this public accidentally and decided to keep it that way.
Maybe this code will be useful for someone.

## P.S.
This code will not work for UserGate Management Center case without python libraries that at the time of writing this are provided for UserGate partners only