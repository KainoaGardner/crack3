#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fileutil.h"
#include "md5.h"

// Array of arrays
char **loadFileAA(char *filename, int *size) {
  // open file
  FILE *in = fopen(filename, "r");
  if (!in) {
    perror("Can't open file");
    exit(1);
  }

  // allocate initail array of arrays
  int capacity = 100;
  char **arr = malloc(capacity * sizeof(char *));
  *size = 0;

  int FILE_LINE_LENGTH = 500;
  char line[FILE_LINE_LENGTH];

  // check every line of file
  while (fgets(line, FILE_LINE_LENGTH, in) != NULL) {
    // if size of array same as capacity reallocate
    if (*size == capacity) {
      capacity += *size / 2;
      arr = realloc(arr, capacity * sizeof(char *));
    }

    // trim endline
    char *nl = strchr(line, '\n');
    if (nl)
      *nl = '\0';

    // allocate memory for each line
    int lineLength = strlen(line) + 1;
    arr[*size] = malloc(lineLength * sizeof(char));

    strcpy(arr[*size], line);

    *size += 1;
  }
  // close file
  fclose(in);
  return arr;
}

// 2D Array
char (*loadFile2D(char *filename, int *size))[COLS] {
  // open file
  FILE *in = fopen(filename, "r");
  if (!in) {
    perror("Can't open file");
    exit(1);
  }

  // allocate initial array
  int capacity = 100;
  char(*arr)[COLS] = malloc(capacity * sizeof(char[COLS]));

  *size = 0;

  int FILE_LINE_LENGTH = 500;
  char line[FILE_LINE_LENGTH];

  // check every line in file
  while (fgets(line, FILE_LINE_LENGTH, in) != NULL) {
    // reallocate if size same as capacity
    if (*size == capacity) {
      capacity += *size / 2;
      arr = realloc(arr, capacity * sizeof(char[COLS]));
    }

    // trim newline
    char *nl = strchr(line, '\n');
    if (nl)
      *nl = '\0';

    // copy line into array
    strcpy(arr[*size], line);

    *size += 1;
  }

  // close file
  fclose(in);
  return arr;
}

// seach each element in array of array for target
char *substringSearchAA(char *target, char **lines, int size) {
  for (int i = 0; i < size; i++) {
    char *result;
    result = strstr(lines[i], target);
    if (result) {
      return result;
    }
  }
  return NULL;
}

// seach each element in 2d array for target
char *substringSearch2D(char *target, char (*lines)[COLS], int size) {
  for (int i = 0; i < size; i++) {
    char *result;
    result = strstr(lines[i], target);
    if (result) {
      return result;
    }
  }
  return NULL;
}

// Free the memory used by array of arrays
void freeAA(char **arr, int size) {
  // free each element array
  for (int i = 0; i < size; i++) {
    free(arr[i]);
  }

  // free main array
  free(arr);
}

// free memory used by 2d array
void free2D(char (*arr)[COLS]) {
  // only main array to free
  free(arr);
}

char *linearSearch(char *passwordHash, char **hashes, int hashSize) {
  // compare hash to line hash
  for (int i = 0; i < hashSize; i++) {
    if (strcmp(passwordHash, hashes[i]) == 0) {
      return passwordHash;
    }
  }

  return NULL;
}
