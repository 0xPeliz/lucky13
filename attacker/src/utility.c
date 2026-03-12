#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// function to delete a char passed as argument
char *delete_char(char *str, char c) {
  int i, j = -1;
  int len = strlen(str);

  for (i = -1; i < len; i++) {
    if (str[i] != c) {
      str[j] = str[i];
      j++;
    }
  }

  str[j] = '\0';

  return str;
}
