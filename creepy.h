#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define w 32 // word size in bits
#define r 20 // based on security estimates
#define P32 0xB7E15163 // Magic constants for key setup
#define Q32 0x9E3779B9
// derived constants
#define bytes   (w / 8) // bytes per word
#define c       ((b + bytes - 1) / bytes) // key in words, rounded u
#define R24     (2 * r + 4)
#define lgw     5                         // log2(w) -- wussed out
// Rotations
#define ROTL(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
#define ROTR(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))

#ifndef _CREEPY_H_
#define _CREEPY_H_

struct inf {
	char *filename;
	char *type;
	//DEPRECATED char *pass;
	int volume;
};

void rc6_key_setup(const char *K, int b);
void rc6_block_encrypt(const unsigned int *pt, unsigned int *ct);
void rc6_block_decrypt(const unsigned int *ct, unsigned int *pt);
void encrypt_process(FILE* fin, int vol, unsigned char *list1, unsigned int *list2, FILE* fout);
void decrypt_process(FILE* fin, int vol, unsigned char *list1, unsigned int *list2, FILE* fout);
void usegroup(struct inf* Inf, char* filename, char* type, char* key, char* volume, int j);
#endif