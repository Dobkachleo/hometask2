#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "creepy.h"

int main(int argc,char *argv[])
{
	if (argc>1) {
		if (strcmp(argv[1],"help")==0) {
			printf("Help (general view): path-to-file flag key "
				"size_of_plain_or_decrypted_file\nYou must calculate decrypted "
				"file volume (dvol) with this formula yourself:\ndvol=evol/16, "
				"where evol - encrypted file volume.");
		} else 
			if (argc%5==0) {
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
				for (int j=0;j<num_of_ops;j++)
					usegroup(Inf,argv[j*4+1],argv[j*4+2],argv[j*4+3],argv[j*4+4],j);
				free(Inf);
			} else printf("Some arguments were missed");
	} else printf("Where are all arguments?!");
	return 0;
}