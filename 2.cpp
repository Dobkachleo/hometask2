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

unsigned int S[R24 - 1]; // Key schedule
void rc6_key_setup(const char *K, int b)
{
	int i=0, j=0, s, v;
	unsigned int L[(32 + bytes - 1) / bytes]; // Big enough for max b
	unsigned int A=0, B=0;
	L[c - 1] = 0;
	for (i = b - 1; i >= 0; i--)
		L[i / bytes] = (L[i / bytes] << 8) + K[i];
	S[0] = P32;
	for (i = 1; i <= 2 * r + 3; i++)
		S[i] = S[i - 1] + Q32;
	v = R24;
	if (c > v) v = c;
	v *= 3;

	for (s = 1; s <= v; s++)
	{
		A = S[i] = ROTL(S[i] + A + B, 3);
		B = L[j] = ROTL(L[j] + A + B, (A + B));
		i = (i + 1) % R24;
		j = (j + 1) % c;
	}
};
void rc6_block_encrypt(const unsigned int *pt, unsigned int *ct)
{
	unsigned int A, B, C, D, t, u, x;
	int i, j;
	A = pt[0];
	B = pt[1];
	C = pt[2];
	D = pt[3];
	B += S[0];
	D += S[1];
	for (i = 2; i <= 2 * r; i += 2)
	{
		t = ROTL(B * (2 * B + 1), lgw);
		u = ROTL(D * (2 * D + 1), lgw);
		A = ROTL(A ^ t, u) + S[i];
		C = ROTL(C ^ u, t) + S[i + 1];
		x = A;
		A = B;
		B = C;
		C = D;
		D = x;
	}
	A += S[2 * r + 2];
	C += S[2 * r + 3];
	ct[0] = A;
	ct[1] = B;
	ct[2] = C;
	ct[3] = D;
};
void rc6_block_decrypt(const unsigned int *ct, unsigned int *pt)
{
	unsigned int A, B, C, D, t, u, x;
	int i, j;
	A = ct[0];
	B = ct[1];
	C = ct[2];
	D = ct[3];
	C -= S[2 * r + 3];
	A -= S[2 * r + 2];
	for (i = 2 * r; i >= 2; i -= 2)
	{
		x = D;
		D = C;
		C = B;
		B = A;
		A = x;
		u = ROTL(D * (2 * D + 1), lgw);
		t = ROTL(B * (2 * B + 1), lgw);
		C = ROTR(C - S[i + 1], t) ^ u;
		A = ROTR(A - S[i], u) ^ t;
	}
	D -= S[1];
	B -= S[0];
	pt[0] = A;
	pt[1] = B;
	pt[2] = C;
	pt[3] = D;
};
struct inf {
	char *filename;
	char *type;
	//DEPRECATED char *pass;
	int volume;
};
int main(int argc,char *argv[])
{
	if (argc>1) {
		if (strcmp(argv[1],"help")==0) {
			printf("Help");
		} else 
			if (argc%5==0) {
				unsigned int ct[4], pt[4];
				int num_of_ops=((argc-1)/4);
				struct inf* Inf=(struct inf*)malloc(num_of_ops*16);
				/*DEPRECATED
				rc6_key_setup("1234",8);
				pt[0]=0x12;
				pt[1]=0x3a;
				pt[2]=0xb1;
				pt[3]=0x22;
				rc6_block_encrypt(pt,ct);
				rc6_block_decrypt(ct,pt);
				*/
				for (int j=0;j<num_of_ops;j++) {
					Inf[j].filename=argv[j*4+1];
					Inf[j].type=argv[j*4+2];
					rc6_key_setup(argv[j*4+3],8);
					Inf[j].volume=atoi(argv[j*4+4]);
					char name[13]="output00.txt";
					name[6]=((j+1)/10)+int('0');
					name[7]=((j+1)%10)+int('0');
					int vol=Inf[j].volume;
					unsigned char *list1=(unsigned char*)malloc(vol*sizeof(unsigned char));
					unsigned int *list2=(unsigned int*)malloc(4*vol*sizeof(unsigned int));
					FILE* fout;
					fout = fopen(name,"wb");
					FILE* fin; 
					fin = fopen(Inf[j].filename,"rb");
					if (Inf[j].type[0]=='c') {
						fread(list1, sizeof(unsigned char), vol, fin);
						for (int i=0;i<vol;i++) {
							for (int l=0; l<4; l++)
								pt[l]=list1[i];
							rc6_block_encrypt(pt,ct);
							for (int l=0; l<4; l++)
								list2[4*i+l]=ct[l];
						}
						fwrite(list2, sizeof(unsigned int), 4*vol, fout);
					}  else
						if (Inf[j].type[0]=='d') {
							fread(list2, sizeof(unsigned int), 4*vol, fin);
							for (int i=0;i<vol;i++) {
								for (int l=0; l<4; l++)
									pt[l]=list2[4*i+l];
								rc6_block_decrypt(pt,ct);
								list1[i]=ct[0];
							}
							fwrite(list1, sizeof(unsigned char), vol, fout);
						} else printf("Invalid flag");
					fclose(fin);
					fclose(fout);

					free(list1);
					free(list2);
				}
				free(Inf);
			} else printf("Some arguments were missed");
	} else printf("Where are all arguments?!");
	return 0;
}