Scribe: The record-replay mechanism
=====================================

Abstract
--------

Scribe is a low-overhead multi-threaded application record-replay mechanism.

Scribe introduces new lightweight operating system mechanisms, rendezvous and
sync points, to efficiently record nondeterministic interactions such as
related system calls, signals, and shared memory accesses.  Rendezvous points
make a partial ordering of execution based on system call dependencies
sufficient for replay, avoiding the recording overhead of maintaining an exact
execution ordering.  Sync points convert asynchronous interactions that can
occur at arbitrary times into synchronous events that are much easier to
record and replay.

For more details about the theory behind it, you can read the
[Scribe paper](http://www.ncl.cs.columbia.edu/publications/sigmetrics2010_scribe.pdf).

The [Scribe slides](http://viennot.biz/scribe-slides/) might also be interesting
to look at. Press _z_ to show the menu, press _space_ to go forward.
Be aware that the images are only seen with Chrome.


Project Organisation
---------------------

The Scribe project is divided in four different ones:

- [The Linux Kernel](/nviennot/linux-2.6-scribe)
- [The Userspace C Library](/nviennot/libscribe)
- [The Python Library](/nviennot/py-scribe)
- [The Tests](/nviennot/tests-scribe)

Installing Scribe
---------------------

### Prerequisites:

- GCC and its friends
- CMake
- Python 3 (**Make sure you are using Python 3, not 2**)
- Cython (**At least version 0.13**)

### Instructions:

1. Install the kernel

        git clone git://github.com/nviennot/linux-2.6-scribe.git
        cd linux-2.6-scribe
        make menuconfig
        make
        make install

2. Install the C library

        git clone git://github.com/nviennot/libscribe.git
        cd libscribe
        cd build
        cmake ..
        make install

3. Install the python library and userspace tools

        git clone git://github.com/nviennot/py-scribe.git
        cd py-scribe
        ./setup install

4. (Optional) Install the test suite

        git clone git://github.com/nviennot/tests-scribe.git

Using Scribe
-------------

py-scribe provides three scripts: record, replay, profiler.

1. Record an application

        $ record date
        Fri Dec 17 00:16:25 EST 2010

2. Replay an execution from a log file

        $ replay date.log
        Fri Dec 17 00:16:25 EST 2010

3. Look at the recorded log file in a human readable format

        $ profiler date.log
        ---[cut]---
        [02] clock_gettime() = 0
        [02]     data: non-det output, ptr = 0xbfca15e0, size = 8, 4d0af253 0c1deab6
        [02]     --fence(412)--
        ---[cut]---

Detailed documentation
-----------------------

- For the kernel implementation details, read the
[scribe kernel documentation](/nviennot/linux-2.6-scribe/blob/master/Documentation/scribe.md).
