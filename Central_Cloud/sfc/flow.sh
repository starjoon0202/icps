#!/bin/sh


python3.5 sff_client.py --remote-sff-ip 192.168.56.101 --local-port 6634 --remote-sff-port 6633 --sfp-id 97 --sfp-index 255 --inner-src-ip 192.168.0.1 --inner-dest-ip 192.168.56.103 --inner-src-port 10000 --inner-dest-port 20000 --ctx1 192.168.56.103 --encapsulate vxlan-nsh-ethernet-legacy
