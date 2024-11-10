#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

#include "fileutil.h"

#define PASS_LEN 50 // Maximum length any password will be.
#define HASH_LEN 33 // Length of hash plus one for null.

// compare two strings alphabeticly
int alphabeticSort(const void *a, const void *b) {
  char **aa = (char **)a; // cast a to pointer to char pointer
  char **bb = (char **)b; // cast b to pointer to char pointer
  return strcmp(*aa, *bb);
}

// create a list of passwords with 0-9 added to end of a base password
char **getVariantPasswords(char *basePassword, int *size) {
  int capacity = 15;
  int passwordSize = strlen(basePassword);

  // create array of passwords
  char **arr = malloc(capacity * sizeof(char *));
  *size = 0;

  // add the original password
  arr[*size] = malloc(strlen(basePassword) * sizeof(char));
  strcpy(arr[*size], basePassword);
  *size += 1;

  // for int 0-9 add digit to end of orignal password and add it to arr
  for (int i = 0; i < 10; i++) {
    char temp[passwordSize + 2];
    strcpy(temp, basePassword);
    char addedDigit[2];
    sprintf(addedDigit, "%d", i);
    strcat(temp, addedDigit);

    arr[*size] = malloc(strlen(temp) * sizeof(char));
    strcpy(arr[*size], temp);

    *size += 1;
  }

  // return password arr
  return arr;
}

int main(int argc, char *argv[]) {
  // check args
  if (argc < 3) {
    printf("Usage: %s hash_file dictionary_file\n", argv[0]);
    exit(1);
  }
  printf("file loaded.\n");

  // get array of strings from hash file
  int size;
  char **hashes = loadFileAA(argv[1], &size);

  // sort array of strings alphabeticly
  qsort(hashes, size, sizeof(char *), alphabeticSort);

  // open dict file
  FILE *dictFile = fopen(argv[2], "r");
  if (!dictFile) {
    fprintf(stderr, "Can't open %s for reading\n", argv[2]);
    exit(1);
  }

  int cracked = 0;
  char password[PASS_LEN];

  // for each password in dict file check if its variants in hash array
  while (fgets(password, PASS_LEN, dictFile) != NULL) {
    // trim newline
    char *nl = strchr(password, '\n');
    if (nl)
      *nl = '\0';

    // get array of password variations
    int variantSize;
    char **variantPasswords = getVariantPasswords(password, &variantSize);

    // for each password variation get hash and compare with hash array
    for (int i = 0; i < variantSize; i++) {
      // hash password
      char *passwordHash = md5(variantPasswords[i], strlen(password));

      // binary seach password in hash array
      char **foundPassword =
          bsearch(&passwordHash, hashes, size, sizeof(char *), alphabeticSort);

      /* char *foundPassword = linearSearch(passwordHash, hashes, size); */

      // if found print and incerment cracked
      if (foundPassword) {
        printf("%s %s\n", *foundPassword, variantPasswords[i]);
        cracked++;
      }
      free(passwordHash);
    }

    // free the variant password array of strings
    freeAA(variantPasswords, variantSize);
  }

  printf("%d hashes cracked!\n", cracked);

  // close file and free hashe array
  fclose(dictFile);
  freeAA(hashes, size);
}
