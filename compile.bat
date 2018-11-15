@echo off
rem
rem	This file creates a new IDA.INT file (comments database).
rem

rem NLSPATH should point to a directory with IDA.HLP file!
set nlspath=.

win\loadint   comment.cmt ida.int
if errorlevel 1 goto error
win\loadint64 comment.cmt ida64.int
if errorlevel 1 goto error
win\btc ida.int idabase.tmp
if errorlevel 1 goto error
copy idabase.tmp ida.int
del idabase.tmp
win\btc ida64.int idabase.tmp
if errorlevel 1 goto error
copy idabase.tmp ida64.int
del idabase.tmp
goto exit
:error
pause
:exit