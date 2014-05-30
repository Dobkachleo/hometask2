#include "creepy.h"

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
}
void rc6_block_encrypt(const unsigned int *pt, unsigned int *ct)
{
	unsigned int A, B, C, D, t, u, x;
	int i;
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
}
void rc6_block_decrypt(const unsigned int *ct, unsigned int *pt)
{
	unsigned int A, B, C, D, t, u, x;
	int i;
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
}
void encrypt_process(FILE* fin, int vol, unsigned char *list1, unsigned int *list2, FILE* fout) {
	unsigned int ct[4], pt[4];
	fread(list1, 1, vol, fin);
	for (int i=0;i<vol;i++) {
		for (int l=0; l<4; l++)
			pt[l]=list1[i];
		rc6_block_encrypt(pt,ct);
		for (int l=0; l<4; l++)
			list2[4*i+l]=ct[l];
	}
	fwrite(list2, sizeof(unsigned int), 4*vol, fout);
}
void decrypt_process(FILE* fin, int vol, unsigned char *list1, unsigned int *list2, FILE* fout) {
	unsigned int ct[4], pt[4];
	fread(list2, sizeof(unsigned int), 4*vol, fin);
	for (int i=0;i<vol;i++) {
		for (int l=0; l<4; l++)
			pt[l]=list2[4*i+l];
		rc6_block_decrypt(pt,ct);
		list1[i]=ct[0];
	}
	fwrite(list1, sizeof(unsigned char), vol, fout);
}
void usegroup(struct inf* Inf, char* filename, char* type, char* key, char* volume, int j) {
	Inf[j].filename=filename;
	if (fopen(Inf[j].filename,"r")==NULL) printf("File hasn\'t existed");
	else {
		Inf[j].type=type;
		rc6_key_setup(key,8);
		Inf[j].volume=atoi(volume);
		char name[13]; strcpy(name,"output00.txt");
		name[6]=((j+1)/10)+'0';
		name[7]=((j+1)%10)+'0';
		int vol=Inf[j].volume;
		unsigned char *list1=(unsigned char*)malloc(vol*sizeof(unsigned char));
		unsigned int *list2=(unsigned int*)malloc(4*vol*sizeof(unsigned int));
		FILE* fout; fout = fopen(name,"wb");
		FILE* fin; fin = fopen(Inf[j].filename,"rb");
		if (Inf[j].type[0]=='c') {
			encrypt_process(fin,vol,list1,list2,fout);
		} else
			if (Inf[j].type[0]=='d') {
				decrypt_process(fin,vol,list1,list2,fout);
			} else printf("Invalid flag");
		fclose(fin);
		fclose(fout);

		free(list1);
		free(list2);
	}
}