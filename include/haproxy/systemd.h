#ifndef _HAPROXY_SYSTEMD_H
#define _HAPROXY_SYSTEMD_H

int sd_notify(int unset_environment, const char *message);
int sd_notifyf(int unset_environment, const char *format, ...);

int sd_listen_fds_with_names(int unset_environment, char ***names);
int sd_listen_fds(int unset_environment);

#endif
