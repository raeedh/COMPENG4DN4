
/* This file gives a simple example of C code padding and
alignment. First, structs are defined that each contain a single basic
int type. Then a struct is defined that contains all three types. The
size and starting address of each is output. 
*/

#include <stdio.h>

int main()
{

  /* Create a short int (2 bytes). */
  short int si;

  /* Create an int (4 bytes). */
  int i;

  /* Create a long int (8 bytes). */
  long int li;

  /* #pragma pack(1) */

  /* Create a struct type with all of the above member types. */
  struct
  {
    short int si;
    int i;
    long int li;
  } three_int_data_instance;

  printf("size of short int = %ld bytes \n", sizeof(si));
  printf("size of int = %ld bytes \n", sizeof(i));
  printf("size of long int = %ld bytes \n", sizeof(li));

  printf("size of struct containing short int, int, and long int = %ld\n",
	 sizeof(three_int_data_instance));

  printf("\n");

  printf("Struct memory assignment: \n");
  printf("%p\n", &three_int_data_instance.si);
  printf("%p\n", &three_int_data_instance.i);
  printf("%p\n", &three_int_data_instance.li);

}


