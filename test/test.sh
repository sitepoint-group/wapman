#!/bin/bash

echo -n "rkscli: "
read whatever
sleep 0.1
echo "Wireless Encryption Type: [0] quit, [1] OPEN, [2] WEP, or [3] WPA"
sleep 0.1
echo -n "Wireless Encryption Type: "
sleep 0.1
read value
sleep 0.1
echo "VALUE: ${value}"
