#ifndef _HAPROXY_SYSTEMD_H
#define _HAPROXY_SYSTEMD_H

int sd_notify(int unset_environment, const char *message);
int sd_notifyf(int unset_environment, const char *format, ...);

#endif
