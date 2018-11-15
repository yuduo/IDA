/*

        This program prints ASCII table of the screen

*/

#include <stdio.h>

int display_page(int page)
{
  printf("\nPAGE %d%c\n", page, 15-page);
  for ( int i=' '; i < 256; i++ )
  {
    if ( (i%16)==0 )
      printf(" %02X:", i);
    printf(" %c", i);
    if ( (i%16)==7 )
      printf(" ");
    if ( (i%16)==15 )
      printf("\n");
  }
}

int main()
{
  display_page(0);
  display_page(1);
  putchar(15);
}
