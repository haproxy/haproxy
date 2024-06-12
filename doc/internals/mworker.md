# Master Worker

2024-06-12

## History

### haproxy-systemd-wrapper

Back in 2013, distributions are discussing the adoption of systemd as the
default init, this was controversial but fedora and archlinux already uses it.
At this time HAProxy still had a multi-process model, and the way haproxy is
working was incompatible with the daemon mode.

Systemd is compatible with traditionnal forking services, but somehow HAProxy
is different. To work correctly, systemd needs a main PID, this is the PID of
the process that systemd will supervises.

With `nbproc 1` that could work, since systemd is able to guess the main PID,
and even to read a PID file. But there is something uncommon that HAProxy is
doing for a reload, which is not supported by systemd. Indeed the reload is in
fact a new haproxy process, which will ask the old one to leave. This means the
new main PID is supposed to change, but systemd is not supporting this, so it
will just see the previous leaving and consider that the service broke and kill
every other processes, meaning the new haproxy.

With `nbproc > 1` this is worse, systemd is confused with all the processes,
because they are independent, so there is not really a main process to
supervise.

The systemd-wrapper appeared in HAProxy 1.5, it's a separated binary, which
starts haproxy, so systemd can use the wrapper as the main PID, and the wrapper
never change PID. Upon a reload, which is done with a SIGUSR2 signal the wrapper
will launch a `haproxy -sf`. This was a non-intrusive work which a first step to
deploy in systemd environments. Later contributions would add the support for
upgrading the wrapper binary upon a reload.

However the wrapper suffered from several problems:

- It needed a intermediate haproxy process, it's basically a daemon mode, but
  instead of the first process leaving to daemonize, it is kept in foreground to
  waitpid() on all workers. Which means you need the wrapper + the -Ds + the
  haproxy workers, and each reload start a new -Ds.
- it was difficult to integrate new features since it wasn't in haproxy itself
- there were multiple issues with handling the failures during reload

### mworker V1

HAProxy 1.8 got ride of the wrapper which was replaced by the master worker
mode. This first version was basically a reintegration of the wrapper features
within HAProxy. HAProxy is launched with the -W flag, read the configuration and
then fork. In mworker mode, the master is usually launched as a root process,
and will do chroot operations then setuid in the workers.

Like the wrapper, the master handle the SIGURS2 signal to reload, it is also
able to forward the SIGUSR1 signal to the workers, to ask for a soft stop.
The reload uses the same logic than the standard `-sf` method, but instead of
starting a new process, it will exec() with -sf in the same PID. Which means
that haproxy could upgrade its binary during the reload.

Once the SIGUSR2 signal is received, the master would block signals and unregister
signals handler so no signals would halt haproxy reload, as it could kill the
master to receive a USR2 if the signal is not register yet after the exec.

When doing the exec() upon a reload, a new argv array is constructed by copying
the current argv and adding `-sf` and the list of PIDs in the children list, as
well as the oldpids list.

When the workers are started, the master will first deinit the poller and clean
the FDs that are not needed anymore (inherited fd need to be kept however), then
the master will do a wait() loop instead of the haproxy polling loop, which will
wait for its workers to leave, or for a signal.

When reloading haproxy, a non-working configuration could exits the master,
which could end in killing all previous workers. This is a complex situation to
handle, since all configuration parsing code was not written to let a process
alive upon a failure. To handle this problem, an atexit() callback was used, so
haproxy would reexec() upon a configuration loading failure, without any
configuration, and without trying to fork new workers. This is called the
master-worker "wait mode".

The master-worker mode also comes with a feature which automates the seamless
reload (-x), meaning it would select the stats socket from the configuration to
be added to the -x parameter for the next reload, so the FD of the bind could be
retrieved automatically.

The master is supervising the workers, when a current worker (not a previous one
from before the reload) is exiting without being asked for a reload, the master
will emit an "exit-on-failure" error and will kill every workers with a SIGTERM
and exits with the same error code than the failed master, this behavior can be
changed by using the "no exit-on-failure" option in the global section.

While the master is supervising the workers using the wait() function, the
workers is also surpervising the master. To achieve this, there is a pipe
between the master and the workers. The FD of the worker side of the pipe is
inserted in the poller so it can watch for a close. When the pipe is closed this
means the master left, and this is not supposed to happen, so it could have
crash. When it happens all workers are leaving. To survive the reloads of the
master, the FD are saved in environment variables (HAPROXY_MWORKER_PIPE_{RD,WR})

The master-worker mode could be activated by using either "-W" or
"master-worker" in the global section of the configuration, but it is prefered
to use "-W".

The pidfile is usable in master-worker mode, instead of writing the PIDs of all
workers, this will only write the PID of the master.

A systemd mode (-Ws) could also be used, it behaves the same way as -W, but will
keep the master in foreground, and will send status messages to systemd using
the sd_notify API.

### mworker V2

HAProxy 1.9 go a little bit further with the master worker, instead of using the
mworker_wait() fuction from V1, it uses the haproxy polling loop, so the signals
will be handled directly by haproxy polling loop, removing the specific code.

Instead of using 1 pipe per haproxy instance, the V2 is using a socketpair per
worker and the polling loop allows real network communication using these
socketpairs. It needs to keep 1 FD per worker in the master, so they can be
reused after a reload. The master keeps a linked list of processes,
mworker_proc, containing socketpairs fd, PID, relative pid... This list is then
serialized in the HAPROXY_PROCESSES environment variable to be unserialized upon
a reload and the FD reinserted in the poller.

Since the FD are in the poller, there is a special flag in the listeners
LI_O_WORKER, which specify that some FD mustn't be used in the worker, these FD
are unbind once in the worker.

Meanwhile the thread support was implemented in haproxy, since mworker shares
more code than before when using the polling loop, the nbthread configuration
variable is not used for instancing the master, and the master will always
remain with only 1 thread.

The HAPROXY_PROCESSES structures allow to store a lot more thing, the number of
reload for each worker is kept, the PID etc...

The socketpairs are useful for bi-directional communication, so each socketpair
are connected to a stats applet on the worker side, so the master could access
to a stats socket for each worker.

The master implements a CLI proxy, which is an analyzer which is able to parse
CLI input, which will split individual CLI commands and redirect them to the
right worker. This is implemented like the HTTP pipelining with command being
sent and responsed one after another. This proxy could be accessed by using the
master CLI which is only bound using the -S option of the haproxy command.
Special prefixed using @ syntax are used to select the right worker.

The master CLI implements its own commands set like `show proc` which shows the
content of the HAPROXY_PROCESSES structure.

A 'reload' command was implemented so the reload could be asked from the master
CLI without using the SIGUSR2 signal.

### more features in mworker V2

HAProxy 2.0 implements a new configuration section called `program` this section
allows to handle the start and stop of executables with the master-worker. One
could launch the dataplane API from haproxy for example. The programs are
shown in the `show proc` command. The programs will be added to the
HAPROXY_PROCESSES structure. The option 'start-on-reload' allows to configure
the behavior of a program during an haproxy reload, it can either start a new
instance of the program or keep the previous one.

A `mworker-max-reloads` keyword was added in the global section, it allows to
limit the number of reload a worker can endure. That helps limiting the number
of remaining worker processes. This will send a SIGTERM to the worker once it
reach this value, instead of a SIGUSR1, so any stuck worker is killed.

Version and starting time were added to HAPROXY_PROCESSES so they could be
displayed in `show proc`.

HAProxy 2.1 added user/group to the program section so they could change their
uid after the fork.

HAProxy 2.5 added the reexec of haproxy in wait mode after a successful loading,
instead of doing it only after a configuration failure. It is useful to clear
the memory of the master because charging the configuration from the master can
take a lot of RAM, and there is no simple wait to free everything and decrease
the memory space of the process.

In HAProxy 2.6, the seamless reload with the master-worker changed, instead of
using a stats socket declared in the configuration, this uses the internal
socketpair of the previous worker. The change is actually simple, instead of
doing a `-x /path/to/previous/socket` it does a `-x sockpair@FD` using the FD
number that can be found in HAPROXY_PROCESSES. With this change the stats socket
in the configuration is less useful and everything can be done from the master
CLI.

With 2.7, the reload mecanism of the master CLI evolved, with previous versions,
this mecanism was asynchronous, so once the `reload` command was received, the
master would reload, the active master CLI connection was closed, and there was
no way to return a status as a response to the `reload` command. To achieve a
synchronous reload, a dedicated sockpair is used, one side uses a master CLI
applet and the other side wait to receive a socket. When the master CLI receives
the `reload` command, it takes the FD of the active master CLI session, sends it
in the socketpair and then does an exec. The FD is then stuck in the kernel
during the reload, because the poller is disabled. Once haproxy reloaded and the
poller active, the FD of the master CLI connection is received, so HAProxy can
reply a success or failure status for the reload. When built with
USE_SHM_OPEN=1, a shm is used to keep the warnings and errors when loading the
configuration in a shared buffer so this could survive the rexec in wait mode
and then be dumped as a response to the `reload` command after the status.

In 2.9 the master CLI command `hard-reload` was implemented, it works the same
way as the `reload` command, but instead of exec() with -sf for a soft-stop, it
starts with -st to achieve a hard stop on the previous worker.

Version 3.0 got rid of the libsystemd dependencies for sd_notify() after the
events of xz/openssh, the function is now implemented directly in haproxy in
src/systemd.c.
