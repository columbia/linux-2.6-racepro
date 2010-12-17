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
