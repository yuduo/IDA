
/*
        Program to get scan codes of keystrokes
*/

#include <windows.h>
#include <stdio.h>
#include <set>

int main()
{
  HANDLE h = GetStdHandle( STD_INPUT_HANDLE );
  DWORD evpending;
  FILE *fp = fopen("out", "w");
  std::set<int> used;
  INPUT_RECORD ir;
  while ( true )
  {
    ReadConsoleInput(h,&ir,1,&evpending);
    int key = ir.Event.KeyEvent.uChar.AsciiChar;
    int scan = ir.Event.KeyEvent.wVirtualScanCode;
    if ( ir.EventType == KEY_EVENT
      && ir.Event.KeyEvent.bKeyDown
      && used.find(key) == used.end() )
    {
      static const char ignore[] = { 0x1D,0x2A,0x38,0x36,0x3A,0x45,0x46,0 };
      if ( strchr(ignore, ir.Event.KeyEvent.wVirtualScanCode) != NULL )
        continue;

      printf("0x%02X, 0x%02X\n", key, scan);
      fprintf(fp, "'%c', 0x%02X\n", key, scan);
      fflush(fp);
      used.insert(key);
      if ( scan == 1 )
        break;
    }
  }
}
