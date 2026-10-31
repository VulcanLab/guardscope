# Release review: the mock harness

Written before sharing the repository with anyone outside the project
(a release gate from docs/DESIGN.md section 12). Reviewed by the project
owner.

## What the tool is

The mock harness is a small program that performs 15 fixed actions on a
computer: it makes network connections, starts processes, writes files,
and reads two files. The actions come from a fixed, hash-verified list.
It runs inside a test setup that the repository also provides, next to
the software that a runtime control uses to watch tool calls. It exists
so a coverage measurement can run without a real agent harness. It does
not contain an AI model, does not talk to any real service, and does not
read real secrets: the two "credential" files it reads are empty
placeholders created by the test setup.

## Could someone misuse it?

The actions it performs are the same actions any program can already
perform with a few lines of ordinary code: connect to an address, start
a process, write a file, read a file. The tool adds no capability that
the operating system does not already give every user program. It does
not evade anything, does not hide itself, does not exploit a flaw, and
does not contain attack techniques. Someone could point it at a machine
they should not use, but they could do the same with any scripting
language; the tool does not make that easier or harder.

We considered two specific concerns:

1. Reading credential files. The actions read two named files, not a
   search for secrets. The test setup creates these files with fake
   content. The tool records that a read happened, never what was read.
2. The fixed action list is public. Anyone can see the 15 actions and
   the paths and ports they use. Publishing the list does not reveal
   anything about any deployed system; the list describes the test
   setup, not any real deployment.

## What the tool is not

It is not a testing framework for someone else's systems, not an attack
tool, and not a harness that runs AI agents. It is one component of a
measurement framework, useful only together with the rest of the
repository.

## Conclusion

The mock harness is safe to release. No conditions are attached.
