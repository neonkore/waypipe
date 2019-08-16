Contributing guidelines
===============================================================================

## Formatting

To avoid needless time spent formatting things, this project has autoformatting
set up. Yes, it's often ugly, but after using it long enough you'll forget that
code can look nice. Python scripts are formatted with black[0], and C code with
clang-format[1]. The script `autoformat.sh` at the root of the directory should
format all source code files in the project.

[0] https://github.com/python/black
[1] https://clang.llvm.org/docs/ClangFormat.html

## Types

* Typedefs should be used only for function signatures, and never applied to
  structs.
* `short`, `long`, and `long long` should not be used, in favor of `int16_t`
  and `int64_t`.
* All wire-format structures should use fixed size types. It's safe to assume
  that buffers will never be larger than about 1 GB, so buffer sizes and
  indices do not require 64 bit types when used in protocol message headers.
* `printf` should be called with the correct format codes. For example, `%zd`
  for `ssize_t`, and the `PRIu32` macro for `uint32_t`.
* Avoid unnecessary casts.

## Comments

Explain precisely that which is not obvious. `/* ... */` is preferred to
`// ...` for longer comments; the leading `/*` and trailing `*/ do not need
lines of their own. Use Doxygen style (`/**`) for functions and structs that
need commenting, but not to the point where it hinders source code readability.
Waypipe is not a library.

## Memory and errors

All error conditions should be handled, including the errors produced by
allocation failures. (It is relatively easy to test for allocation failure
by `LD_PRELOAD`ing a library that redefines malloc et al.; see for instance
"mallocfail" and "failmalloc". `ulimit -v` may be less effective.)

Some errors are unrecoverable, and for those cases Waypipe should shut down
cleanly. For instance, if Waypipe cannot replicate a file descriptor, then an
application connected through it will almost certainly crash, and it's better
to have Waypipe exit instead. Other errors can safely ignored -- if fine
grained damage tracking fails, a sane fallback would be to assume that an
entire surface is damaged.
