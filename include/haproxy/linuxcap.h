#ifndef _HAPROXY_LINUXCAP_H
#define _HAPROXY_LINUXCAP_H

int prepare_caps_for_setuid(int from_uid, int to_uid);
int finalize_caps_after_setuid(int from_uid, int to_uid);

#endif /* _HAPROXY_LINUXCAP_H */
