/*------------------------------------------------------------*/
/* filename -       stddlg.cpp                                */
/*                                                            */
/* function(s)                                                */
/*                  Member functions of following classes     */
/*                      TFileInputLine                        */
/*                      TSortedListBox                        */
/*                      TSearchRec                            */
/*                      TFileInfoPane                         */
/*------------------------------------------------------------*/

/*------------------------------------------------------------*/
/*                                                            */
/*    Turbo Vision -  Version 1.0                             */
/*                                                            */
/*                                                            */
/*    Copyright (c) 1991 by Borland International             */
/*    All Rights Reserved.                                    */
/*                                                            */
/*------------------------------------------------------------*/


#define Uses_MsgBox
#define Uses_TKeys
#define Uses_TFileInputLine
#define Uses_TEvent
#define Uses_TSortedListBox
#define Uses_TSearchRec
#define Uses_TFileInfoPane
#define Uses_TDrawBuffer
#define Uses_TFileDialog
#define Uses_TSortedCollection
#include <tv.h>
#ifdef __IDA__
#include <prodir.h>
#endif

#include <stdio.h>
#ifdef __NT__
#include <windows.h>
#endif

#ifdef __MSDOS__
char &shiftKeys = *(char *)MK_FP( 0x0, 0x417 );
unsigned char getShiftState(void) { return shiftKeys; }
#endif // __MSDOS__

#define cpInfoPane "\x1E"

TFileInputLine::TFileInputLine( const TRect& bounds, short aMaxLen ) :
    TInputLine( bounds, aMaxLen )
{
    eventMask = eventMask | evBroadcast;
}

void TFileInputLine::handleEvent( TEvent& event )
{
    TInputLine::handleEvent(event);
    if( event.what == evBroadcast &&
        event.message.command == cmFileFocused &&
        !(state & sfSelected)
      )
        {
        size_t dsize = dataSize();
        if( (((TSearchRec *)event.message.infoPtr)->attr & FA_DIREC) != 0 )
            {
            qstrncpy( data, ((TSearchRec *)event.message.infoPtr)->name, dsize );
            qstrncat( data, SDIRCHAR, dsize );
            qstrncat( data, ((TFileDialog *)owner)->wildCard, dsize );
            }
        else
            qstrncpy( data, ((TSearchRec *)event.message.infoPtr)->name, dsize );
        drawView();
        }
}

TSortedListBox::TSortedListBox( const TRect& bounds,
                                ushort aNumCols,
                                TScrollBar *aScrollBar) :
    TListBox(bounds, aNumCols, aScrollBar),
    shiftState( 0 ),
    searchPos( -1 )
{
    showCursor();
    setCursor(1, 0);
}

void TSortedListBox::handleEvent(TEvent& event)
{
  char curString[maxViewWidth];
  char newString[maxViewWidth];

  int oldValue = focused;
  TListBox::handleEvent( event );
  if ( oldValue != focused )
    searchPos = -1;
  if ( event.what == evKeyDown )
  {
    if ( event.keyDown.charScan.charCode != 0 )
    {
      int value = focused;
      if ( value < range )
        getText( curString, value, sizeof(curString) );
      else
        *curString = EOS;
      int oldPos = searchPos;
      if ( event.keyDown.keyCode == kbBack )
      {
        if ( searchPos == -1 )
          return;
        curString[searchPos] = EOS;
        searchPos--;
        if( searchPos == -1 )
          shiftState = (uchar)event.keyDown.controlKeyState;
      }
      else if ( (event.keyDown.charScan.charCode == '.') )
      {
        char *loc = strchr( curString, '.' );
        if ( loc == 0 )
          searchPos = -1;
        else
          searchPos = ushort(loc - curString);
      }
      else
      {
        searchPos++;
        if ( searchPos == 0 )
          shiftState = (uchar) event.keyDown.controlKeyState;
        curString[searchPos] = event.keyDown.charScan.charCode;
        curString[searchPos+1] = EOS;
      }
      void *k = getKey(curString);
      list()->search( k, value );
      if ( value < range )
      {
        getText( newString, value, sizeof(newString) );
        if( strnicmp( curString, newString, searchPos+1 ) == 0 )
        {
          if( value != oldValue )
          {
            focusItem(value);
            setCursor( ushort(cursor.x+searchPos), ushort(cursor.y) );
          }
          else
            setCursor(ushort(cursor.x+(searchPos-oldPos)), ushort(cursor.y) );
        }
        else
          searchPos = oldPos;
      }
      else
        searchPos = oldPos;
      if ( searchPos != oldPos ||  isalpha( event.keyDown.charScan.charCode ) )
        clearEvent(event);
    }
  }
}

void* TSortedListBox::getKey( const char *s )
{
    return (void *)s;
}

void TSortedListBox::newList( TSortedCollection *aList )
{
    TListBox::newList( aList );
    searchPos = -1;
}

TFileInfoPane::TFileInfoPane( const TRect& bounds ) :
    TView(bounds)
{
    eventMask |= evBroadcast;
}

#ifdef __NT__
// for working with 'realname' in DOS-emulator
static int (__stdcall *getLongName)(const char *, char *, int) = NULL;
static void fname_startup(void)
{
// Can't use static linkage - win95 & NT4 not have this function
    if((unsigned)GetVersion() >= 0xF0000000) // use in rtm only - speed :)
      *(FARPROC *)&getLongName = GetProcAddress(GetModuleHandleA("kernel32"),
                                                "GetLongPathNameA");
}

#if defined(_MSC_VER)
class tvinit { public: tvinit(void) { fname_startup(); }};
static tvinit tv_initializer;
#elif defined(__BORLANDC__)
#pragma startup fname_startup
#else
#error "Unknown compiler"
#endif

#endif  //__NT__

void TFileInfoPane::draw()
{
    Boolean PM;
    TDrawBuffer b;
    ushort  color;
    dos_ftime *time;
    char  path[MAXPATH], *pfn;
    size_t fpos;

    qstrncpy( path, ((TFileDialog *)owner)->directory, sizeof(path) );
#ifdef __NT__
    if(getLongName) getLongName(path, path, sizeof(path));
#endif // __NT__
    qstrncat( path, ((TFileDialog *)owner)->wildCard, sizeof(path) );
    fexpand( path, sizeof(path) );

    color = getColor(0x01);
    b.moveChar( 0, ' ', color, ushort(size.x) );
    if ( (int)strlen(path)+3 > size.x ) {
      b.moveStr( 3, path+(strlen(path)-size.x+4), color );
      b.moveStr( 1, "..", color );
    } else {
      b.moveStr( 1, path, color );
    }
    writeLine( 0, 0, ushort(size.x), 1, b );

    b.moveChar( 0, ' ', color, ushort(size.x) );
    pfn   = file_block.name;  // unification
#ifdef __NT__
    if(getLongName) { // w95 & NT4 don't have this function
      char  *p = strrchr(path, DIRCHAR);

      if(p) { // PARANOYA
        qstrncpy(p+1, pfn, path+sizeof(path)-p-1);
        if((fpos = getLongName(path, path, sizeof(path))) != 0) {
          if(path[--fpos] == DIRCHAR && path[fpos-1] != ':') path[fpos] = '\0';
          pfn = strrchr(path, DIRCHAR) + 1;
        }
      }
    }
#endif // __NT__
    fpos = strlen(pfn);
    if(fpos+3 <= (size_t)size.x) fpos = 1;
    else {
      b.moveStr( 1, "..", color );
      pfn += fpos-size.x+4;
      fpos = 3;
    }
    b.moveStr( ushort(fpos), pfn, color );
    writeLine( 0, 1, ushort(size.x), 1, b);

    b.moveChar( 0, ' ', color, short(size.x) );
    if( *(file_block.name) != EOS )
        {
        char buf[10];
	qsnprintf(buf, sizeof(buf), "%d", file_block.size);
        b.moveStr( 3, buf, color );

        time = (dos_ftime *) &file_block.time;
        b.moveStr( 21, months[time->ft_month], color );

	qsnprintf(buf, sizeof(buf), "%02d", time->ft_day);
        b.moveStr( 25, buf, color );

        b.putChar( 27, ',' );

	qsnprintf(buf, sizeof(buf), "%d", time->ft_year+1980);
        b.moveStr( 28, buf, color );

        PM = Boolean(time->ft_hour >= 12 );
        time->ft_hour %= 12;

        if( time->ft_hour == 0 )
            time->ft_hour = 12;

        qsnprintf(buf, sizeof(buf), "%02d", time->ft_hour);
        b.moveStr( 34, buf, color );
        b.putChar( 36, ':' );

        qsnprintf(buf, sizeof(buf), "%02d", time->ft_min);
        b.moveStr( 37, buf, color );

        b.moveStr( 39, PM ? pmText : amText, color );
        }

    writeLine(0, 2, ushort(size.x), 1, b );
    b.moveChar( 0, ' ', color, ushort(size.x) );
    writeLine( 0, 3, ushort(size.x), ushort(size.y-2), b);
}

TPalette& TFileInfoPane::getPalette() const
{
    static TPalette palette( cpInfoPane, sizeof( cpInfoPane )-1 );
    return palette;
}

void TFileInfoPane::handleEvent( TEvent& event )
{
    TView::handleEvent(event);
    if( event.what == evBroadcast && event.message.command == cmFileFocused )
        {
        file_block = *((TSearchRec *)(event.message.infoPtr));
        drawView();
        }
}

#ifndef NO_TV_STREAMS
TStreamable *TFileInfoPane::build()
{
    return new TFileInfoPane( streamableInit );
}
#endif  // ifndef NO_TV_STREAMS
