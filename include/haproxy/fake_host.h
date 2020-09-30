#ifndef FAKE_HOST_HEDER
#define FAKE_HOST_HEDER
/*
 Todo socks4a we must skip local DNS step and send domain to socks4 server.
 However this program cannot work if localy remote IP is absent.
 So this is fake address for SOCKS4 backend.
 1. If we detect that socks4 and cannot resolve domain localy, then
 we setup backend server to use this fake host.

 2. Next when connection to server is created it checks if server has fake flag (2 places in code - copies.).
 If it is so, then connection copies hostname field from server to itself.
 
 3. Next on handshake connection checks if it has text string "requested domain", if it is so, it does 4A protocol,
 otherwise 4.
 
 FAKE_SOCKS4A_IP is used at that step to catch that domain string is absent, but fake ip is set.
 This means step (2) from above was skipped, i.e. some copy-paste in code was not modified yet.
 
 There is slim chance that was valid request to this fake IP using SOCKS4. Well, don't use SOCKS4 for this IP :)
*/
#define FAKE_SOCKS4A_HOST "10.10.10.10"
#define FAKE_SOCKS4A_IP (0x0A0A0A0A)

#endif