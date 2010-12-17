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

  The most relevant functions related to the context are
  [`do_start()`](../scribe/context.c#L199),
  [`scribe_emergency_stop()`](../scribe/context.c#L253) and
  [`scribe_attach()`](../scribe/context.c#L364),
  [`scribe_detach()`](../scribe/context.c#L459).

- **The queues**. They contain a list of event relative to a process.

  When a recorded task does a `gettimeofday()`, the buffer that needs to be
  recorded will be saved in a event, which is inserted in the process' queue
  which later on gets dumped in the log file.

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

- **The scribed tasks**. TODO

- **The resources**. Each access to a shared resource must be serialized,
  and the access order must be preserved across record/replay.
  (see the [presentation](http://viennot.biz/scribe-slides/#15)).
  [resource.c](../scribe/resource.c) implements the logic behind it.

- **RDTSC**. TODO

- **The memory**. TODO

- **The signals**. TODO

- **The Userspace Accesses**. TODO
