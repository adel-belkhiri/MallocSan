
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char digits[10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};

int main(int argc, char *argv[]) {
  static char **table;
  char *line;
  FILE *out = stderr;
  unsigned crc;
  int i, j, size, loop_size, test_access;

  fprintf(out, "Program start\n");
  char *str = malloc(10);
  str[0] = 'A'; str[1] = 'B'; str[2] = 'C'; str[3] = 0;
  fprintf(out, "This is a problem %s\n", str);
  
  if(argc < 2) size = 20;
  else size = atoi(argv[1]);
  if(argc < 3) loop_size = 1;
  else loop_size = atoi(argv[2]);
  if(argc < 4) test_access = 0;
  else test_access = atoi(argv[3]);
  
  fprintf(out, "Malloc table in main %p\n", main);
  table = malloc(sizeof(char *) * size);

  for(i = 0; i < size; i++) {
    line = malloc(sizeof(char) * 10);
    table[i] = line;
    strncpy(line, "Bonjour", 8);
    line[7] = digits[i % 10];
    line[8] = 0;
  }

  for(i = 0; i < size; i++) {
    line = table[i];
    strncpy(line, "Bonjour", 8);
    line[7] = digits[i % 10];
    line[8] = 0;
  }

  // for(i = 0; i < size; i++) {
  //   fprintf(out,"Line %d, %s\n", i, table[i]);
  // }
//    for(j = 0; j < size; j++) crc += table[j][0];

  crc = 0;
  for(i = 0; i < loop_size; i++) {
    for(j = 0; j < size; j++) 
    { 
      line = table[j];
      crc += 1;
      crc += line[0];
    }
  }

  if(test_access > 0) {
      for(i = size - 3; i < size + 2; i++) {
          fprintf(out, "Check access to table[%d]\n", i);
          line = table[i];
      }
  }

  for(i = 0; i < size; i++) {
    line = table[i];
    fprintf(out,"Free line %d, %p in table %p\n", i, line, table);
    free(line);
  }
  
  fprintf(out, "Free table, crc = %d\n", crc);
  free(table);
}

