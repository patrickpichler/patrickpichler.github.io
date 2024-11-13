+++
author = "Patrick Pichler"
title = "Figuring out which helpers are available in what kernel version in eBPF"
date = "2024-11-10"
description = "This post explores different ways of figuring out which eBPF helpers are available to what program types at certain kernel versions."
tags = [
    "ebpf"
]
+++

eBPF helpers are a vital part of any eBPF program. It is often not easy to figure out, which helper
you have available for a certain program type at a given Linux Kernel Version. The goal of this blog
post is, to document some ways of answering the question "Can I use bpf helper abc in a xyz program
at Linux Kernel version n".

## docs.ebpf.io

One pretty amazing resource for anything eBPF related is [docs.ebpf.io](https://docs.ebpf.io).
It was started by [Dylan Reimerink](https://github.com/dylandreimerink) (as far as I can tell).

{{< img "ebpf_docs.png" "eBPF docs landing page" >}}

Not only does it contain documentation for most eBPF helpers,program types and
maps, but also includes a kernel version it was introduced in. Take for example
the `bpf_sk_storage_get` helper. The documentation for it can be found under
[linux/helper-function/bpf_spin_lock/](https://docs.ebpf.io/linux/helper-function/bpf_sk_storage_get/).

{{< img "ebpf_docs_spin_lock.png" "eBPF docs page about bpf_spin_lock" >}}

The first thing you see on the page is the version it was introduced, in this case it was
`v5.2`. There is also quick overview what the helper does, as well as how to use it. You will also
find a list of program types the helper is available in, which is exactly what we were searching
for.

{{< img "ebpf_docs_spin_lock_program_types.png" "eBPF docs page about bpf_spin_lock" >}}

One word of caution though. All the docs on the website are manually created, meaning that there
can be mistakes, as well as just missing data. When a helper is only later than its introduction
available to a certain program type, you will find a small label next to the program type with the
starting version it was introduced.

{{< img "ebpf_docs_bpf_sk_storage_get_program_types.png" "There are small labels with the version support was introduced" >}}

In case you notice any missing data or error on the page, I would suggest you head over to the docs
[GitHub repo](https://github.com/isovalent/ebpf-docs) and open a PR with the fix. The maintainers
there are friendly and contributions are welcomed.

## bpftool

If you are writing eBPF programs, you probably heard about
[bpftool](https://github.com/libbpf/bpftool) before. In case you do not know it, `bpftool` is part
of the `libbpf` project and offers various utilities, such as listing all eBPF programs and maps
currently loaded, to dumping the content of specific maps and even dumping the BTF for a given
binary. It is a pretty powerful and incredibly useful tool to know how to use.

One feature that I only learned recently, is the `bpftool feature probe kernel` command. The output
of this subcommand is a list of all supported program types/map types and helpers by program type.

Now, if you want to figure out if e.g. syscall programs support the `bpf_spin_lock` helper on our
current kernel version, all we need to do is run `bpftool feature probe kernel | less`, search for
`eBPF helpers supported for program type syscall` and go through the list of helpers it lists. If
`bpf_spin_lock` is there, it means it is supported on the current kernel version, if not, it is not
supported.

{{< img "bpftool.png" "bpftool in action" >}}

The `bpftool` method does have a few downsides though. One of the most obvious is, that it will
only show the available helpers/program types for the current kernel version. There is simply no
way of using it to figure out if a certain helper is present at a certain kernel version, without
first running the kernel locally. This is just the way `bpftool` works, as it will try to load a
small eBPF program with just a call to the helper.

Another problem I encountered with `bpftool` (and haven't fully figured out yet) is, that is
sometimes fails to determine the helper support for certain program types. Here an example output
```
eBPF helpers supported for program type tracing:
	Could not determine which helpers are available
```

## Using Bootlin (aka exploring Linux Kernel Source Code)

As we have seen before, both `bpftool` and docs.ebpf.io have their downsides, when trying to figure
out what helpers you have available in eBPF program types at certain kernel versions. The ultimate
method, but also the one including the most work, is to simply have a look at the Linux Kernel
Source Code of whatever version you want to support.

Let's try to figure out if we can use the `bpf_spin_lock` helper in an eBPF program of type
`BPF_PROG_TYPE_TRACING` on Linux Kernel version `v5.10`.

We first start by navigating to the
[include/linux/bpf_types.h](https://elixir.bootlin.com/linux/v5.10/source/include/linux/bpf_types.h)
file for our target kernel version on Bootlin. It contains definitions for all the program types
supported in that version of the Linux Kernel.

{{< img "bootlin_bpf_types.png" "include/linux/bpf_types.h file in Linux 5.10" >}}

The verifier also uses this file to map each program
type to some verifier options, based on some macro definitions we can find
[here](https://elixir.bootlin.com/linux/v5.10/source/kernel/bpf/verifier.c#L28). To figure out if
a helper can be used in a certain program type, all we need to do is to find the corresponding
verifier ops and have a look at the `get_func_proto` function pointer. The verifier ops follow a
specific naming pattern. It will just take the second argument passed to `BPF_PROG_TYPE` and append
`_verifier_ops` (as seen in the verifier macro definition).

{{< img "bootlin_verifier_prog_type_macro.png" "Macro used by verifier to locate program types ops" >}}

In our case, we want to figure out if `bpf_spin_lock` is
available for program type `BPF_PROG_TYPE_TRACING`. In
[include/linux/bpf_types.h](https://elixir.bootlin.com/linux/v5.10/source/include/linux/bpf_types.h#L49),
the second argument passed to the definition is `tracing`. This means the verifier ops we are
searching for is called `tracing_verifier_ops`. We can enter this in the search box on the upper
right with the placeholder text `Search Identifier`. There should be only a single result.

{{< img "bootlin_tracing_verifier_ops.png" "Definition of tracing_verifier_ops" >}}

Now, let's trace assigned value of `get_func_proto`, `tracing_prog_func_proto`. We can do this,
by clicking on `tracing_prog_func_proto` and select the location under `Defined in 1 files as
function`.

{{< img "bootlin_tracing_prog_func_proto.png" "tracing_prog_func_proto function" >}}

The way `tracing_prog_func_proto` works is pretty straight forward. In the end it is a series of
some switch statements, that will either match the requested helper `bpf_func_id` and returns a
function pointer to the helpers definition, or return `NULL`. `bpf_spin_lock` is not in the switch
statement of `tracing_prog_func_proto`, so we go ahead and jump to the function call that is called
in the default branch of the switch. We continue this until we either find that `NULL` is returned,
or we find the helper id we are searching for. In our case, `bpf_spin_lock` never shows up and
`NULL` will be returned, meaning `bpf_spin_lock` cannot be used in Linux `v5.10` for
`BPF_PROG_TYPE_TRACING`. When you think back at docs.ebpf.io, tracing is listed to be a program
type usable with `bpf_spin_lock`, where is this coming from? Well, we can try to do the same
exercise for newer kernel version to try figuring out. The next LTS version is `v5.15`. When doing
the tracing in that version, we end up with a return value for `bpf_spin_lock` in
`BPF_PROG_TYPE_TRACING`, meaning it is supported. The easiest would now be to do some sort of binary
search until we can pinpoint the version the function is introduced, but this is an exercise that
is left to the reader.

## Conclusion

As you can see, it is not always easy to figure out if you can use a certain eBPF helper in one
of your programs. While some short cuts in the form of `bpftool` and
[docs.ebpf.io](https://docs.ebpf.io) exist, they not always give an definite answer. In the end it
is always good to simply open the Linux Kernel source code and verify yourself if the helper you
need is present or not.

In case anyone knows a better more efficient way of finding helper availability for program types,
please let me know. Feel free to reach out to me on any of the linked social media platform (or
feel free to open an issue/PR on the GitHub repo where this blog lives).
