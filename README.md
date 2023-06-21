# libssl-keylog

this is a kernel plugin which logs all tls master keys to stdout
in a format which wireshark can use to decrypt tls sessions \
http://udn.realityripple.com/docs/Mozilla/Projects/NSS/Key_Log_Format \

### usage
place the plugin `*KERNEL` in `config.txt`

get your vita stdout on your pc, use a small script or grep to filter out the tls logs

example:\
`ncat -tlvk 3333 | tee >(grep --line-buffered --text "CLIENT_RANDOM" - > keylog.txt)`


connect your vita to a network your pc can intercept and setup keylog file in wireshark
https://wiki.wireshark.org/TLS.md#using-the-pre-master-secret
