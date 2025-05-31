#!/bin/bash
iptables -A INPUT -s 103.255.254.86 -j DROP
iptables -A OUTPUT -d 103.255.254.86 -j DROP