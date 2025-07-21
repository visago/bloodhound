# bloodhound - HTTP Reverse Proxy Sniffer

This code was initially generated using [Claude](https://claude.ai/) and modified to fit my purpose.

## Environment Variables

* TargetUrl - Target host URL (Default https://httpbin.org/)
* ListenAddr - Listen addr:port (Default 0.0.0.0:25663)
* BoneFolder - Folder to store sniffed bones to

## Docker

A dockered version is avilable at visago/bloodhound:latest

```
mkdir ./bones
chmod 777 ./bones # So the bloodhound user in docker can access it
docker run -p 25663:25663 -e TargetUrl=https://httpbin.org/  -e BoneFolder=/bones -v ./bones:/bones visago/bloodhound:latest
```
