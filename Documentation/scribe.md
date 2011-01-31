Scribe: The record-replay mechanism
=====================================

Kernel implementation overview
-------------------------------

### Where is the source ?
The scribe source can be easily seen with:

    $ git diff base

Pretty much all of it is in `scribe/`.

### The pieces
The kernel implementation is separated in different parts:

- **The events** which are used in two places:
  - The log file, which is the output of a scribe recording
  - The protocol of the scribe device (through read() and write())

  They are defined in [scribe_api.h](../include/linux/scribe_api.h#L55)

- **The scribe context**, a sort of container for the task tree that is being
  scribed.

  The [`struct scribe_context`](../include/linux/scribe.h#L259) holds the
  associated data to represent a `scribe_context`.

  The most relevant functions related to the context are
  [`do_start()`](../scribe/context.c#L199) and
  [`scribe_emergency_stop()`](../scribe/context.c#L253).

  The way to start a scribe session is to start the context with `do_start`,
  create a new task with the `CLONE_NEWPID` flag, and that will be the init
  process.
  Once [`scribe_set_attach_on_exec()`](../scribe/context.c#L334) is called,
  the session will officially starts when the init task called `execev`.
  The rational behind this choice is that `execve` is the only place where we
  can remove any non-determinism inherited from the parent.

- **The queues**. They contain a list of event relative to a process.

  When a recorded task does a `gettimeofday()`, the buffer that needs to be
  recorded will be saved in a event, which is inserted in the process' queue
  which later on gets dumped in the log file.

  The structs associated with the queues are:
  [`struct scribe_stream`](../include/linux/scribe.h#L48) and
  [`struct scribe_queue`](../include/linux/scribe.h#L72).
  The difference between a `scribe_queue` and a `scribe_stream` is that a
  `scribe_queue` is tied with a specific `scribe_context` and a pid (hence a
  specific task), while a `scribe_stream` may be used unbound to a context,
  with no reference counting. The `scribe_stream` type is mostly used for the
  notification queue (when the kernel needs to communicate to userspace).

  A few interesting functions:
  [`scribe_get_queue_by_pid()`](../scribe/event.c#L63),
  [`__scribe_queue_events_at()`](../scribe/event.c#L212) and
  [`scribe_dequeue_event()`](../scribe/event.c#L302).

- **The event pump**. It takes care of serializing (recording) and deserializing
  (replaying) the events to/from a log file.

  The pump operates by running a kernel thread in the background.

  The two big entry points are:
  [`event_pump_record()`](../scribe/pump.c#L246) and
  [`event_pump_replay()`](../scribe/pump.c#L437).

- **The device**. Userspace communicates through the device to tell the
  kernel what to do ([`dev_write()`](../scribe/device.c#L94)). It also receive
  notification from the kernel ([`dev_read()`](../scribe/device.c#L137)).

  The device is responsible to instantiate the scribe context and the pump,
  which is in [`dev_open()`](../scribe/device.c#L189).

- **The scribed tasks**. When a task is scribed, `task->scribe` points to a
  [`struct scribe_ps`](../include/linux/scribe.h#L423).

  A task gets attached and detached from a `scribe_context` with:
  [`scribe_attach()`](../scribe/context.c#L364),
  [`scribe_detach()`](../scribe/context.c#L459).

  - `scribe_attach()` is called from `copy_process()` and `do_exec()`. Those are
  the only two places a task can be attached.
  - `scribe_detach()` is called from `do_exit()` and `scribe_enter_syscall()`.
  The later is used when the context gracefully request a stop.

- **The resources**. Each access to a shared resource must be serialized,
  and the access order must be preserved across record/replay.
  (see the [presentation](http://viennot.biz/scribe-slides/#15)).
  [resource.c](../scribe/resource.c) implements the logic behind it.

- **RDTSC**. TODO

- **The memory**. TODO

- **The signals**. TODO

- **The Userspace Accesses**. TODO


The log file
==============

Log file structure
-------------------

The log file consists of a stream of events. An event is simply an array of
bytes. Events will be shown in this document in their human representation.

Each event belongs to a task, except for the init event and the pid event. An
event is associated with a pid. There exists a function `events_of` such as:

                          events_of
        (logfile, pid) ---------------> list of events that belongs to that pid

In the log file, pids are not repeated with each event for efficiency. Below is
an example of how it works in the log file:

        event_pid=10
        event1
        event2
        event3
        event_pid=20
        event4
        event5
        event6

Events 1,2,3 are associated with pid=10, and events 4,5,6 are associated with pid=20.

Rule: For each pid, `events_of(log, pid)` should be terminated with a
`eof_queue` event. It allows the kernel to make sure that there is not any
events to be waited for.  During the replay, a process can golive when its
entire event queue has been consumed.


Log file verbosity
--------------------

There are different log verbosity levels. Level `i+1` contains all the information of level `i`.

- level 0 (minimal verbosity): the log file contains only the necessary data for a faithful
  replay.
- level 1: the log file contains all syscall returns values.
- level 2: the log file contains extra syscall information:
  - The syscall numbers
  - Where the syscall ended. This is needed to indent the human readable
    representation of the log file on each syscall.
- level 3: contains the signal cookies (dependencies of sent/delivered signals).
- level 4: contains extra information about resources:
  - Which object was locked
  - Where the resource was unlocked. This is needed to indent the human readable
    representation of the log file on each syscall.
- level 5: contains extra information about the memory tracking: owned pages
  embed the page address.
- level 6: contains extra information about user accesses (`copy_from_user()` and friends).
  The userspace pointer is embedded withing the event.
- level 7: contains all non-deterministic user accesses data.
- level 8: Always do the resource locking, even when it's not needed.
- level 9: Always put fences, even when not needed.
- level 10: Registers are saved before each syscalls.

Example of a recording in level 0:

        [02] data: size = 96, 00000801 00000000 00000000 000a1ddb 000081a4 00000002 00000000 00000000...
        [02] syscall() = 0xb73f4000
        [02] syscall() = 0xb773e000
        [02] syscall() = 0
        [02] syscall() = 0
        [02] data: size = 96, 00000009 00000000 00000000 00000003 00002190 00000001 00000000 00000005...
        [02] syscall() = 0

The same snippet, but recorded in level 20:

        [02] fstat64() = 0
        [02]     resource lock, type = files_struct (spinlock), object = 0xf676b500, serial = 11
        [02]     resource lock, type = file, object = 0xf6b5a480, serial = 0
        [02]       resource lock, type = inode, object = 0xf6d8daf0, serial = 0
        [02]     data: non-det output, ptr = 0xb7775ae0, size = 96, 00000801 00000000 00000000 000a1dd...
        [02]     --fence(281)--
        [02] regs: eip: 0073:b777e424, eflags: 00000246, eax: 000000c0, ebx: 00000000, ecx: 00200000,...
        [02] --fence(282)--
        [02] --fence(283)--
        [02] mmap_pgoff() = 0xb7432000
        [02] regs: eip: 0073:b777e424, eflags: 00000246, eax: 000000c0, ebx: 00000000, ecx: 00001000,...
        [02] --fence(284)--
        [02] --fence(285)--
        [02] mmap_pgoff() = 0xb777c000
        [02] regs: eip: 0073:b777e424, eflags: 00000206, eax: 00000006, ebx: 00000003, ecx: b7774ff4,...
        [02] --fence(286)--
        [02] --fence(287)--
        [02] close() = 0
        [02]     resource lock, type = files_struct (spinlock), object = 0xf676b500, serial = 12
        [02] regs: eip: 0073:b777e424, eflags: 00000292, eax: 000000c5, ebx: 00000001, ecx: bffbecec,...
        [02] --fence(288)--
        [02] --fence(289)--
        [02] fstat64() = 0
        [02]     resource lock, type = files_struct (spinlock), object = 0xf676b500, serial = 13
        [02]     resource lock, type = file, object = 0xf66aa300, serial = 0
        [02]       resource lock, type = inode, object = 0xf6fbd830, serial = 0
        [02]     data: non-det output, ptr = 0xbffbecec, size = 96, 00000009 00000000 00000000 0000000...
        [02]     --fence(290)--
        [02] regs: eip: 0073:b777e424, eflags: 00000292, eax: 000000c5, ebx: 00000000, ecx: bffbecec,...
        [02] --fence(291)--
        [02] --fence(292)--
        [02] fstat64() = 0
        [02]     resource lock, type = files_struct (spinlock), object = 0xf676b500, serial = 14
        [02]     resource lock, type = file, object = 0xf66aa300, serial = 1
        [02]       resource lock, type = inode, object = 0xf6fbd830, serial = 1
        [02]     data: non-det output, ptr = 0xbffbecec, size = 96, 00000009 00000000 00000000 0000000...
        [02]     --fence(293)--

Log file grammar
-----------------

**We will assume a maximum log verbosity.**

Legend:

- `1` mean one.
- `1?` means zero or one.
- `*` means zero or more.

### Each `events_of(log, pid)` is:

1. \* `main_block`
2. 1 `eof_queue_event`

Example:

    rdtsc = 0000016205f68540
    brk() = 0x95e0000
    syscall ended
    queue EOF

### A `main_block` is either:

- a `rdtsc_event`: used when the userspace process does a RDTSC instruction.
- a `mem_block`: used when the userspace process accesses some memory.
- a `data_block`: used when a signal is delivered and the context is created.
- a `syscall_block`: used when the userspace process calls a system call.

### A `mem_block` is:

1. 1? `fence_event`
2. \* `mem_public_event`
3. 1 `mem_owned_event`, or 1 `mem_alone_event`

Example:

    --fence(135)--
    mem public, page = b760a000
    mem public, page = b75fe000
    mem owned, page = b760b000, serial = 193

### A `syscall_block` is:

1. 1 `regs_event`
2. \* `sig_block`
3. 1? `mem_block`
4. 1? `bookmark_event`
5. 1 `syscall_event`
6. \* `inner_syscall_block`
7. 1 `syscall_end_event`

Example:

    regs: eip: 0073:b7ff8714, eflags: 00000282, eax: 00000005, ebx: b7ffaafe, ...
    --fence(8)--
    --fence(9)--
    open() = 3
    data: input string, ptr = 0xb7ffaafe, size = 16, "/etc/ld.so.cache"
    --fence(10)--
    resource lock, type = files_struct (spinlock), object = 0xf7214a80, serial = 0
    resource unlock, object = 0xf7214a80
    resource lock, type = inode, object = 0xf6d60570, serial = 1
    resource unlock, object = 0xf6d60570
    resource lock, type = inode, object = 0xf6db8e70, serial = 1
    resource unlock, object = 0xf6db8e70
    resource lock, type = files_struct (spinlock), object = 0xf7214a80, serial = 1
    resource unlock, object = 0xf7214a80
    syscall ended

### A `sig_block` is:

1. 1? `fence_event`
2. 1? `sig_recv_cookie_event`
3. 1 `sig_event`

Example:

    --fence(321)--
    signal recv, cookie = 1
    signal: SIGUSR1, deferred = false, info = 0000000a 00000000 00000000 ...

### A `inner_syscall_block` is either:

- a `res_block`
- a `data_block`
- a `sig_send_cookie_event`

### A `res_block` is either:

1. 1 `res_lock_event`
2. \* `inner_syscall_block`
3. 1 `res_unlock_event`

Example of two nested resource locks:

    resource lock, type = file, object = 0xf6790180, serial = 1
    resource lock, type = inode, object = 0xf516b6f0, serial = 1
    resource unlock, object = 0xf516b6f0
    resource unlock, object = 0xf6790180

or:

1. `res_lock_intr_event`

A `data_block` is:

1. 1? `mem_block`
2. 1 `data_event`
