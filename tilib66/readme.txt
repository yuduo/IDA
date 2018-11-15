TILIB - utility to create type libraries for IDA Pro
----------------------------------------------------

This small utility creates type library (til) files for IDA Pro.
Its functionality overlaps with the "Parse header file".
However, this utility is easier to use and provides more control
over the output. Also, it can handle the preprocessor symbols, while
the built-in command ignores them.

The utility takes a C header file and extract all type information from it.
The extracted type information is stored in an internal format as a type
library file. Type library files can be loaded and used in IDA Pro by
opening the Type Library Window and pressing Insert.

TILIB support only C header files. C++ files (classes, templates, etc) are
not supported, but some popular C++ keywards are recognized and properly handled.
For example, TILIB knows about the inline keyword and properly skips the definition
of the inline function.

Installation
------------

Just copy the tilib executable file into the IDA Pro directory.
If you prefer to keep it in another directory, you will need to
specify the location of the ida.hlp file using the NLSPATH variable:

set NLSPATH=c:\program files\ida

Please note that you do not need to define this variable if you just copy
the tilib executable file to the IDA Pro directory.

Usage
------

If started without parameters, the utility displays a short explanation.
Below are some command line samples.

Parse a header file and create a new type library:

tilib -c -hinput_header_file output_til_file

-c means to create a new type library
-h denotes the name of the input file to read

If you need to parse multiple files into one type library, you may create
a text file with #include directives and specify it as the input.

TILIB can handle input files for Visual Studio, Borland, GCC out of the box.
Please check the confguration files for them in the archive (*.cfg).

If you need to fine tune TILIB for another compiler (or unusual compiler settings),
feel free to copy the provided configuration files and modify them.

TILIB is not very good at error handling and some error messages may be quite
unhelpful (e.g. syntax error). To alleviate this problem, use the -z switch.
If this switch is specified, TILIB will create a .i file with the preprocessed
contents. All recognized type names are prepended with @, like this: @my_type_name.

In some urgent cases, the -e switch may be used to ignore any parsing errors.
Please note that the problematic type definitions will be skipped in this mode.
This switch may be used together with the -R switch to allow type redeclarations.

If your input file uses another header file (e.g. windows.h), you may opt to use
the vc6win.til file instead of parsing it again. For that, just use the -b switch
and specify vc6win.til as the base til. TILIB will load the contents of the
specified file into the memory and parse the input file. All definitions from
windows.h, including the preprocessor definitions, will be avaible:

tilib -c -hinput_header_file -bbase_til_file output_til_file

TILIB can also be used to list the contents of a til file:

tilib -l input_til_file

If the -c switch is not specified, TILIB uses the specified til file as the input
and as the output file. This mode allows you to modify existing til files.

How to create preprocessor macro enums
--------------------------------------

TILIB can also convert selected preprocessor macros into enums. If the input file
has lines like the following:

#define MY_SYMBOL_ONE   1
#define MY_SYMBOL_TWO   2
#define MY_SYMBOL_THREE 3

they can be converted to enum and used in IDA Pro. This is a two step process.
At the first step, we create a .mac file (note the -M switch):

tilib -c -Moutput_mac_file -hinput_header_file output_til_file

The second step is to edit the generated MAC file: to remove undesired macro definitions
and regroup macros if necessary. Macro group names start at the beginning of a line,
symbol definitions are indented:

MY_SYMBOL
  MY_SYMBOL_ONE   1
  MY_SYMBOL_TWO   2
  MY_SYMBOL_THREE 3

Feel free to edit the macro file to your taste.

The third and last step is to specify the macro file as the input for TILIB:

tilib -c -minput_mac_file -hinput_header_file output_til_file

The generated til file will have all normal type definitions and all macro
definitions from the .mac file.


List of supported keywords
--------------------------

Below is the list of supported keywords. If your header files happen to have
an unsupported keyword, you take one of the following actions:

  - edit the input files and remove the unsupported keywords
  - use #define to replace or hide the unsupported keywords
  - use the -D command line switch for the same purpose

__cdecl       do      this      sizeof        __userpurge
__pascal      if      void      static        _BYTE
__stdcall     _es     break     struct        _WORD
__fastcall    _cs     catch     switch        _DWORD
__thiscall    _ss     class     default       _QWORD
__usercall    _ds     const     mutable       _OWORD
__export      asm     float     private       _UNKNOWN
__import      for     short     typedef       __spoils
__thread      int     throw     virtual
__declspec    auto    union     continue
__far         bool    while     register
__near        case    double    template
__huge        char    extern    unsigned
__int8        else    friend    volatile
__int16       enum    inline    __interrupt
__int32       flat    public    namespace
__int64       goto    return    protected
__int128      long    signed    __unaligned

===============================================================================



























































