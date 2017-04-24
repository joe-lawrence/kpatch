Why did that function change?!
==============================

Most likely answers: inline functions or `__LINE__` source code shift.


Intermediate object files
-------------------------

kpatch-build (by default) will cleanup original and patched build objects.  To
determine exactly why a function was modified in a kpatch module, we will want
to inspect those intermediate object files, so instruct kpatch-build to skip
cleanup:
```
  kpatch-build --skip-cleanup klp.patch
```
Original object files can be found in `$TEMPDIR/orig` while patched object
files can be found in the `$TEMPDIR/patched` directory, where `$TEMPDIR` is
set to `$HOME/.kpatch/tmp` by default.


ELF Sections
------------

kpatch-build compiles the kernel and modules with `-ffunction-sections`, which
means each function will end up in its own ELF section.  Inlined functions
however, will not; inlined code will be duplicated in each of its calling
functions' respective sections.  Therefore, the lack of an ELF function
section for can suggest that the compiler might have inlined that code.

The readelf utility can be used to display the ELF sections in an object file:
```
  readelf --wide --sections myfile.o
```
Function sections are named with a `.text.` prefix and have a `PROGBITS` type.

Generating a list of added, common and dropped function sections can be useful
to find inlined functions, including those that might only have been inlined
originally or after patching.
```
  OBJ=arch/x86/kvm/vmx.o

  CACHEDIR=$HOME/.kpatch
  TEMPDIR=$CACHEDIR/tmp
  ORIG=$TEMPDIR/orig/$OBJ
  PATCHED=$TEMPDIR/patched/$OBJ

  readelf --wide --sections $ORIG | awk '$3 ~ /PROGBITS/ && $2 ~ /.text./{print $2}' | \
      sort > readelf.orig
  readelf --wide --sections $PATCHED| awk '$3 ~ /PROGBITS/ && $2 ~ /.text./{print $2}' | \
      sort > readelf.patched

  comm -13 readelf.orig readelf.patched > readelf.added
  comm -12 readelf.orig readelf.patched > readelf.common
  comm -23 readelf.orig readelf.patched > readelf.dropped
```
Summary of kpatch-build report for inline function changes:

| Original function   | Patched function  | Function Report    | Caller(s) Report      |
| --------------------|-------------------|--------------------|-----------------------|
| stand alone         | inline            | -                  | changed               |
| inline              | stand alone       | new                | changed               |
| inline              | inline            | -                  | changed               |


Disassembly
-----------

Examining compiler generated code before and after patching can be time
consuming, but worth the effort to determine why kpatch-build reports new or
changed functions.
```
  FUNC=handle_exception

  objdump --disassemble-all --section=.text.$FUNC $ORIG > objdump.orig
  objdump --disassemble-all --section=.text.$FUNC $PATCHED > objdump.patched
```
To get a foothold in the *patched* source tree with given address offset:
```
  addr2line --exe $PATCHED --section .text.$FUNC 0x73a
```
The same command can be used to retrieve a source code location in the
original object file, however, remember that `kpatch-build` overwrites
`$CACHEDIR/src` when it builds the patched objects.  The file/offsets reported
by `addr2line` are correct, but the files themselves have been updated.

A few sed filters can aid the analysis, especially when running orignal vs.
patched objdump output through difftools:

* Cut section titles to fit inside diff's 40 character context blurbs:
```
  sed -i 's/Disassembly of section //g' objdump.orig objdump.patched
```
* Remove the instruction offset prefix:
```
  sed 's/^[ 0-9a-f]*://g' objdump.orig > objdump.orig.1
  sed 's/^[ 0-9a-f]*://g' objdump.patched > objdump.patched.1
```
* Remove lines with instructions with offsets:
```
  sed "/[a-f0-9]* <$FUNC+0x[a-f0-9]*>/d" objdump.orig.1 > objdump.orig.2
  sed "/[a-f0-9]* <$FUNC+0x[a-f0-9]*>/d" objdump.patched.1 > objdump.patched.2
```

Example
=======

Consider the upstream patch, [ext4: allocate entire range in zero range](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0f2af21aae11972fa924374ddcf52e88347cf5a8)
that fixes CVE-2015-0275.  It modifies a few lines in `ext4_zero_range()`.
```
commit 0f2af21aae11972fa924374ddcf52e88347cf5a8
Author: Lukas Czerner <lczerner@redhat.com>
Date:   Fri Apr 3 00:09:13 2015 -0400

    ext4: allocate entire range in zero range

    Currently there is a bug in zero range code which causes zero range
    calls to only allocate block aligned portion of the range, while
    ignoring the rest in some cases.

    In some cases, namely if the end of the range is past i_size, we do
    attempt to preallocate the last nonaligned block. However this might
    cause kernel to BUG() in some carefully designed zero range requests
    on setups where page size > block size.

    Fix this problem by first preallocating the entire range, including
    the nonaligned edges and converting the written extents to unwritten
    in the next step. This approach will also give us the advantage of
    having the range to be as linearly contiguous as possible.

    Signed-off-by: Lukas Czerner <lczerner@redhat.com>
    Signed-off-by: Theodore Ts'o <tytso@mit.edu>

diff --git a/fs/ext4/extents.c b/fs/ext4/extents.c
index 2e6af88d112f..3cc17aacc4c7 100644
--- a/fs/ext4/extents.c
+++ b/fs/ext4/extents.c
@@ -4797,12 +4797,6 @@ static long ext4_zero_range(struct file *file, loff_t offset,
        else
                max_blocks -= lblk;

-       flags = EXT4_GET_BLOCKS_CREATE_UNWRIT_EXT |
-               EXT4_GET_BLOCKS_CONVERT_UNWRITTEN |
-               EXT4_EX_NOCACHE;
-       if (mode & FALLOC_FL_KEEP_SIZE)
-               flags |= EXT4_GET_BLOCKS_KEEP_SIZE;
-
        mutex_lock(&inode->i_mutex);

        /*
@@ -4819,15 +4813,28 @@ static long ext4_zero_range(struct file *file, loff_t offset,
                ret = inode_newsize_ok(inode, new_size);
                if (ret)
                        goto out_mutex;
-               /*
-                * If we have a partial block after EOF we have to allocate
-                * the entire block.
-                */
-               if (partial_end)
-                       max_blocks += 1;
        }

+       flags = EXT4_GET_BLOCKS_CREATE_UNWRIT_EXT;
+       if (mode & FALLOC_FL_KEEP_SIZE)
+               flags |= EXT4_GET_BLOCKS_KEEP_SIZE;
+
+       /* Preallocate the range including the unaligned edges */
+       if (partial_begin || partial_end) {
+               ret = ext4_alloc_file_blocks(file,
+                               round_down(offset, 1 << blkbits) >> blkbits,
+                               (round_up((offset + len), 1 << blkbits) -
+                                round_down(offset, 1 << blkbits)) >> blkbits,
+                               new_size, flags, mode);
+               if (ret)
+                       goto out_mutex;
+
+       }
+
+       /* Zero range excluding the unaligned edges */
        if (max_blocks > 0) {
+               flags |= (EXT4_GET_BLOCKS_CONVERT_UNWRITTEN |
+                         EXT4_EX_NOCACHE);

                /* Now release the pages and zero block aligned part of pages*/
                truncate_pagecache_range(inode, start, end - 1);
```
kpatch-build
------------

When building a kpatch against a similar vintage RHEL 7 kernel, kpatch-build
reports changes to *three* functions, none of which match the function updated
in the source code:
```
Using cache at /root/.kpatch/src
Testing patch file
checking file fs/ext4/extents.c
Reading special section data
Building original kernel
Building patched kernel
Extracting new and modified ELF sections
extents.o: changed function: ext4_convert_unwritten_extents
extents.o: changed function: ext4_collapse_range
extents.o: changed function: ext4_fallocate
Patched objects: ext4.ko
Building patch module: kpatch-klp.ko
SUCCESS
```

ext4_convert_unwritten_extents
------------------------------

The report notes that `ext4_convert_unwritten_extents` has changed, which is
curious as the patch for CVE-2015-0275 doesn't touch that function.  Run that
function and its object file through objdump and a few sed filters:
```
  OBJ=fs/ext4/extents.o
  FUNC=ext4_convert_unwritten_extents

  CACHEDIR=$HOME/.kpatch
  TEMPDIR=$CACHEDIR/tmp
  ORIG=$TEMPDIR/orig/$OBJ
  PATCHED=$TEMPDIR/patched/$OBJ

  objdump --disassemble-all --section=.text.$FUNC $ORIG > objdump.orig
  objdump --disassemble-all --section=.text.$FUNC $PATCHED > objdump.patched

  sed -i 's/Disassembly of section //g' objdump.orig objdump.patched

  sed 's/^[ 0-9a-f]*://g' objdump.orig > objdump.orig.1
  sed 's/^[ 0-9a-f]*://g' objdump.patched > objdump.patched.1

  sed "/[a-f0-9]* <$FUNC+0x[a-f0-9]*>/d" objdump.orig.1 > objdump.orig.2
  sed "/[a-f0-9]* <$FUNC+0x[a-f0-9]*>/d" objdump.patched.1 > objdump.patched.2
```
The generated code (with address prefixes and offsets filtered) shows the
changes are minimal, consisting of a few immediate register stores:

```
diff -Nup objdump.orig.2 objdump.patched.2
--- objdump.orig.2      2017-04-24 15:03:58.000000000 -0400
+++ objdump.patched.2   2017-04-24 15:05:27.000000000 -0400
@@ -1,5 +1,5 @@

-/root/.kpatch/tmp/orig/fs/ext4/extents.o:     file format elf64-x86-64
+/root/.kpatch/tmp/patched/fs/ext4/extents.o:     file format elf64-x86-64


 .text.ext4_convert_unwritten_extents:
@@ -37,7 +37,7 @@
        4d 85 e4                test   %r12,%r12
        4c 89 e7                mov    %r12,%rdi
        ba 0b 00 00 00          mov    $0xb,%edx
-       be 96 13 00 00          mov    $0x1396,%esi
+       be 9d 13 00 00          mov    $0x139d,%esi
        48 3d 00 f0 ff ff       cmp    $0xfffffffffffff000,%rax
        49 89 c4                mov    %rax,%r12
        45 31 f6                xor    %r14d,%r14d
@@ -57,7 +57,7 @@
        45 31 c0                xor    %r8d,%r8d
        44 89 f1                mov    %r14d,%ecx
        ba 03 00 00 00          mov    $0x3,%edx
-       be a5 13 00 00          mov    $0x13a5,%esi
+       be ac 13 00 00          mov    $0x13ac,%esi
        48 3d 00 f0 ff ff       cmp    $0xfffffffffffff000,%rax
        49 89 c4                mov    %rax,%r12
        48 8d 55 b8             lea    -0x48(%rbp),%rdx
@@ -70,7 +70,7 @@
        4c 89 e7                mov    %r12,%rdi
        45 85 f6                test   %r14d,%r14d
        4c 89 e2                mov    %r12,%rdx
-       be b5 13 00 00          mov    $0x13b5,%esi
+       be bc 13 00 00          mov    $0x13bc,%esi
        48 c7 c7 00 00 00 00    mov    $0x0,%rdi
        89 45 b4                mov    %eax,-0x4c(%rbp)
        8b 45 b4                mov    -0x4c(%rbp),%eax
@@ -97,14 +97,14 @@
        48 c7 c1 00 00 00 00    mov    $0x0,%rcx
        89 44 24 08             mov    %eax,0x8(%rsp)
        8b 45 c4                mov    -0x3c(%rbp),%eax
-       ba b2 13 00 00          mov    $0x13b2,%edx
+       ba b9 13 00 00          mov    $0x13b9,%edx
        44 8b 4d c0             mov    -0x40(%rbp),%r9d
        48 c7 c6 00 00 00 00    mov    $0x0,%rsi
        89 04 24                mov    %eax,(%rsp)
        31 c0                   xor    %eax,%eax
        0f 1f 00                nopl   (%rax)
        4c 89 e2                mov    %r12,%rdx
-       be ba 13 00 00          mov    $0x13ba,%esi
+       be c1 13 00 00          mov    $0x13c1,%esi
        48 c7 c7 00 00 00 00    mov    $0x0,%rdi
        89 45 b4                mov    %eax,-0x4c(%rbp)
        89 de                   mov    %ebx,%esi
```
Working back through the generated files, we can correlate each change to an
offset within the `.text.ext4_convert_unwritten_extents` section, and then back
to a line of code in the source tree:
```
% grep 'be 9d 13 00 00' objdump.patched
  67:   be 9d 13 00 00          mov    $0x139d,%esi
% addr2line --exe $PATCHED --section .text.$FUNC 0x67
/root/.kpatch/src/fs/ext4/extents.c:5020
5020                 handle = ext4_journal_start_reserved(handle,
5021                                                      EXT4_HT_EXT_CONVERT);


% grep 'be ac 13 00 00' objdump.patched
  d4:   be ac 13 00 00          mov    $0x13ac,%esi
% addr2line --exe $PATCHED --section .text.$FUNC 0xd4
/root/.kpatch/src/fs/ext4/ext4_jbd2.h:312
312         return __ext4_journal_start_sb(inode->i_sb, line, type, blocks,
313                                        rsv_blocks);


% grep 'be bc 13 00 00' objdump.patched
 11f:   be bc 13 00 00          mov    $0x13bc,%esi
% addr2line --exe $PATCHED --section .text.$FUNC 0x11f
/root/.kpatch/src/fs/ext4/extents.c:5052
5052                         ret2 = ext4_journal_stop(handle);


% grep 'ba b9 13 00 00' objdump.patched
 186:   ba b9 13 00 00          mov    $0x13b9,%edx
% addr2line --exe $PATCHED --section .text.$FUNC 0x186
/root/.kpatch/src/fs/ext4/extents.c:5045
5045                         ext4_warning(inode->i_sb,
5046                                      "inode #%lu: block %u: len %u: "
5047                                      "ext4_ext_map_blocks returned %d",
5048                                      inode->i_ino, map.m_lblk,
5049                                      map.m_len, ret);


% grep 'be c1 13 00 00' objdump.patched
 1ab:   be c1 13 00 00          mov    $0x13c1,%esi
% addr2line --exe $PATCHED --section .text.$FUNC 0x1ab
/root/.kpatch/src/fs/ext4/extents.c:5057
5057                 ret2 = ext4_journal_stop(handle);
```
Each instance can be traced back to `/root/.kpatch/src/fs/ext4/ext4_jbd2.h`
and preprocessor `__LINE__` usage.  (Chasing through the macros is left as an
exercise for the reader.)  In each case, the source line number was
incremented by seven lines.

The patch can avoid unnecessary changes to `ext4_convert_unwritten_extents()`
with one of the following:
* Maintain line count by trimming / adding comments, blank lines, etc.
* Replacing the macros with hard-coded `__LINE__` values (i.e., the original
  ones).
* Instructing kpatch-build to ignore changes the function with the
  `KPATCH_IGNORE_FUNCTION` macro.


ext4_fallocate
--------------

`ext4_fallocate` is another function that kpatch-build reported as changing,
even though it wasn't modified by the patch.  In this case, we'll work
backwards and try to find out more about the function that the patch did
change, `ext4_zero_range`.

[Cscope](http://cscope.sourceforge.net/) is handy search tool that can tell us
which other functions are calling `ext4_zero_range`:
```
Functions calling this function: ext4_zero_range

  File      Function       Line
0 extents.c ext4_fallocate 4949 return ext4_zero_range(file, offset, len, mode);
```
This information is useful, as short functions that are called by only a few
other functions are prime candidates for inlining.

As stated earlier in _ELF Sections_, kpatch-build compiles the kernel and
modules so that all real (but not inline) functions are  placed in its own
section named `.text.function_name`.  Dumping the section list and grepping
for these:
```
  readelf --wide --sections $ORIG | awk '$3 ~ /PROGBITS/ && $2 ~/.text./{print $2}' | \
      sort > readelf.orig
  readelf --wide --sections $PATCHED| awk '$3 ~ /PROGBITS/ && $2 ~ /.text./{print $2}' | \
      sort > readelf.patched

  grep '\<ext4_zero_range\>' readelf.orig readelf.patched
```
show that `ext4_zero_range` never was a stand-alone function and is not after
the patch.


TODO: there has to be a better, easier way to explain inlined functions other
than saying, "welp, there's only one caller and there's no function section,
so it must have been inlined."  gdb's `disassemble /m` instruction does a
better job than `objdump -S`, but gdb is an interactive program.


ext4_collapse_range
-------------------

Similar results as `ext4_convert_unwritten_extents`, `__LINE__` was
incremented by 7 lines.


v2 patch
--------

The quickest way to avoid `__LINE__` changes to
`ext4_convert_unwritten_extents()` and `ext4_collapse_range()` was to remove a
few comment lines from `ext4_zero_range()`.  That function is already going to
change as it is the target of the patch, and there's a few large comment
blocks that we trim the lines needed to preserve ensuing line numbers.
Version two of the patch adds a hunk that looks like:
```
@@ -4841,13 +4848,6 @@ static long ext4_zero_range(struct file
                if (ret)
                        goto out_dio;
                /*
-                * Remove entire range from the extent status tree.
-                *
-                * ext4_es_remove_extent(inode, lblk, max_blocks) is
-                * NOT sufficient.  I'm not sure why this is the case,
-                * but let's be conservative and remove the extent
-                * status tree for the entire inode.  There should be
-                * no outstanding delalloc extents thanks to the
                 * filemap_write_and_wait_range() call above.
                 */
                ret = ext4_es_remove_extent(inode, 0, EXT_MAX_BLOCKS);
```
With that additional change in place, a kpatch-build of version two reports
changes to `ext4_fallocate()`, which was already determined to be the caller of
inlined `ext4_zero_range()`:
```
Skipping cleanup
Fedora/Red Hat distribution detected
Downloading kernel source for 3.10.0-250.el7.x86_64
Unpacking kernel source
Testing patch file
checking file fs/ext4/extents.c
Reading special section data
Building original kernel
Building patched kernel
Extracting new and modified ELF sections
extents.o: changed function: ext4_fallocate
Patched objects: ext4.ko
Building patch module: kpatch-klp2.ko
SUCCESS
```
