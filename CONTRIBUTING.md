
# Formatting

To avoid needless time spent formatting things, this project has autoformatting
set up. Yes, it's often ugly, but after using it long enough you'll forget that
code can look nice. Python scripts are formatted with black[0], and C code with
clang-format[1]. The script `autoformat.sh` at the root of the directory should
format all source code files in the project.

[0] https://github.com/python/black
[1] https://clang.llvm.org/docs/ClangFormat.html
