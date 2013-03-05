#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include<fcntl.h>
#include<unistd.h>

#define N_BIT_SIZE 1024 
#define SIZE_OF_BLOCK (N_BIT_SIZE/8) 
#define SIZE_OF_BUFFER (N_BIT_SIZE/16)


typedef struct {
    mpz_t n; 
    mpz_t e; 
} public;

typedef struct {
    mpz_t n; 
    mpz_t e; 
    mpz_t d; 
    mpz_t p; 
    mpz_t q;
    mpz_t dp;
    mpz_t dq;
    mpz_t Iq; 
} private;

int Encrypt_Decrypt_with_my_keys(private *pri,public *pub)
{
    FILE *fid;
    char buf[1000]="";
    char temp[100];
    fid=fopen("plain.txt","rt");
    if(fid)
    {
      while(fgets(temp,100,fid)!=NULL)
      {

      strcat(buf,temp);
      }
    fclose(fid);
    }
    else
    perror("Error");
    int l= strlen(buf);
    buf[l]='\0';

    char ci[12000];
    printf("\n\n------ENCRYPTION AND DECRYPTION WITH KEYS THAT I GENERATED--------\n");
    printf("\nInput file name is-->plain.txt\noutput file name-->cipher.txt ");
    printf("\nThe original Message is=\n%s",buf);
    printf("\nLength of Original message=%d",strlen(buf));
    int lenOfEncryptedData =  encrypt(ci,buf,pub->e,pub->n);
    ci[lenOfEncryptedData] = '\0';
    printf("\nEncryprted data=\n%s",ci);
    printf("\nlength of Encrypted data=%d",lenOfEncryptedData);
FILE *ft;
ft=fopen("cipher.txt","wb");
int k;
for(k=0;ci[k]!='\0';k=k+1)
{
putc(ci[k],ft);
}
fclose(ft);

    char decryptedData[strlen(buf) + 1];
    int lenOfDecryptedData = decrypt(decryptedData, ci, lenOfEncryptedData, pri->d,pri->n);
    decryptedData[lenOfDecryptedData] = '\0';
    printf("\nDecrypted data=\n%s", decryptedData);
    printf("\nlength of decrypted data=%d",lenOfDecryptedData);
    if(strcmp(buf, decryptedData) == 0)
    printf("\nSuccess\n");

    return;
}

int der_decoder()
{
    mpz_t n,e,d;
    mpz_init(n);
    mpz_init(e);
    mpz_init(d);
    FILE *fp;
    int count=0;
    unsigned char ch;
    char *fstr;
    int fd;
    int ret;
    fd=open("openss_priv1024.der",O_RDWR);
    ret=read(fd,&ch,1);
    while(ret!=0)
    {
      count++;
      ret=read(fd,&ch,1);
    }
    fstr=malloc(count);
    lseek(fd,0,SEEK_SET);
    ret=read(fd,fstr,count);
    close(fd);
    FILE *fid;
    char buff[1000]="";
    char temp[100];
    fid=fopen("plain2.txt","rt");
    if(fid)
    {
      while(fgets(temp,100,fid)!=NULL)
      {

        strcat(buff,temp);
      }
    fclose(fid);
    }
    else
    perror("Error");

    printf("\n---------OPENSSL RETRIEVED KEYS--from--> openss_priv1024.der key<------\n");
int n_offset,e_offset,d_offset;
unsigned char n_size,e_size,d_size;
n_offset=10;
n_size=fstr[9];
e_size=fstr[9+n_size+2];
e_offset=9+n_size+2+1;
d_offset=e_offset+e_size+3;
d_size=fstr[d_offset-1];
    mpz_import(n,n_size,1,1,0,0,&fstr[n_offset]);
    printf("\nN value is%s\n",mpz_get_str(NULL,16,n));
    mpz_import(e,e_size,1,1,0,0,&fstr[e_offset]);
    printf("e value is %s\n",mpz_get_str(NULL,16,e));
    mpz_import(d,d_size,1,1,0,0,&fstr[d_offset]);
    printf("d value is %s\n",mpz_get_str(NULL,16,d));

    int l= strlen(buff);
    buff[l]='\0';
   
   char ci1[12000];
   printf("\n-----ENCRYPTION AND DECRYPTION WITH OPENSSL KEYS BY RETREIVING THEM---------\n");
   printf("\nInput file name-->plain2.txt");
   printf("\nThe Original message is \n%s",buff);
   printf("\nLength of original message is %d",strlen(buff));
   int lenOfEncryptedData1 =  encrypt(ci1,buff,e,n);
   ci1[lenOfEncryptedData1] = '\0';
   printf("\nEncrypted data: %s\n", ci1);
   printf("\nlength of Encrypted data=%d",lenOfEncryptedData1);
   char decryptedData1[strlen(buff) + 1];
   int lenOfDecryptedData1 = decrypt(decryptedData1, ci1, lenOfEncryptedData1, d,n);
   decryptedData1[lenOfDecryptedData1] = '\0';
   printf("\nDecrypted data: %s", decryptedData1);
   printf("\nlength of  decrytped data=%d",lenOfDecryptedData1);

   if(strcmp(buff, decryptedData1) == 0)
     printf("\nSuccess\n");

   return;
}


void keygeneration(private *pri, public *pub)
{
    char Buffer[SIZE_OF_BUFFER];/*Buffer size is 64 bytes or 512 bits as n=1024bits */
    int t=0;
    mpz_t pi; 
    mpz_t t1;
    mpz_t t2; 
    mpz_t t3;
    mpz_t t4; 
    mpz_init(pi);
    mpz_init(t1);
    mpz_init(t2);
    mpz_init(t3);
    mpz_init(t4);
    srand(time(NULL));/* non repetition of random generated prime numbers*/
    mpz_set_ui(pri->e, 3); /* e=3 */
    
    while( t < SIZE_OF_BUFFER)
    {
    Buffer[t] = rand() % 0xFF;      /* Set the bits of Buffer randomly */
    t++;
    }   
    Buffer[0] |= 0xC0; /*for p value to be relatively large*/
    Buffer[SIZE_OF_BUFFER - 1] |= 0x01;/*for  p value is odd*/
    mpz_import(t1, SIZE_OF_BUFFER, 1, sizeof(Buffer[0]), 0, 0, Buffer);//convert into int
    mpz_nextprime(pri->p, t1);//pick next random prime
    mpz_mod(t2, pri->p, pri->e);/* If p mod e == 1, gcd(pi, e) != 1 */ 
    while(!mpz_cmp_ui(t2, 1))/* prime condition checking*/
    {
      mpz_nextprime(pri->p, pri->p); 
      mpz_mod(t2, pri->p, pri->e);
    }

    /* select q again randomly and p!=q should also be checked */
    do {
    for(t = 0; t < SIZE_OF_BUFFER; t++)
    Buffer[t] = rand() % 0xFF;
    
    Buffer[0] = 0xC0;
    Buffer[SIZE_OF_BUFFER - 1] = 0x01;
   
    mpz_import(t1, (SIZE_OF_BUFFER), 1, sizeof(Buffer[0]), 0, 0, Buffer);
   
    mpz_nextprime(pri->q, t1);
    mpz_mod(t2, pri->q, pri->e);
    while(!mpz_cmp_ui(t2, 1))
    {
      mpz_nextprime(pri->q, pri->q);
      mpz_mod(t2, pri->q, pri->e);
    }
    } while(mpz_cmp(pri->p, pri->q) == 0); /* P!=q condition checking */

    /* Calculate n */
    mpz_mul(pri->n, pri->p, pri->q);
    //coefficient value calculation
    mpz_invert(pri->Iq,pri->q,pri->p);

    /* Compute pi(n) value */
    mpz_sub_ui(t1, pri->p, 1);
    mpz_sub_ui(t2, pri->q, 1);
    mpz_mul(pi, t1, t2);

    /* Calculate d value */
    if(mpz_invert(pri->d, pri->e, pi) == 0)
    {
        mpz_gcd(t1, pri->e, pi);
        printf("gcd(e, pi) = [%s]\n", mpz_get_str(NULL, 16, t1));
        printf("failed of Inversion operation\n");
    }
    //exponent 1 and 2 calculations
    mpz_sub_ui(t1,pri->p,1);
    mpz_mod(t3,pri->d,t1);
    mpz_sub_ui(t2,pri->q,1);
    mpz_mod(t4,pri->d,t2);
    mpz_set(pri->dp,t3);
    mpz_set(pri->dq,t4);
    /* Set public key */
    mpz_set(pub->e, pri->e);
    mpz_set(pub->n, pri->n);

    return;
}
int encrypt(char cipher[], char message[], mpz_t ke,mpz_t kn)
{

    int no_of_blocks = 0;
    int rest_len;
    int msg_len = strlen(message);
    int rest_msg =msg_len;
    char messageblock[SIZE_OF_BLOCK];
    mpz_t m; 
    mpz_init(m);
    mpz_t c; 
    mpz_init(c);
    while(rest_msg > 0)
    {
      int ptr=0;/*Must declared inside as for every loop meesageblock runs from starting*/
    
      if(rest_msg>=SIZE_OF_BLOCK-11)
      rest_len=SIZE_OF_BLOCK - 11;
      else
      rest_len=rest_msg;
      messageblock[ptr++] = 0x00;
      messageblock[ptr++] = 0x02;
      /*Padded bits randomly */
      while(ptr < (SIZE_OF_BLOCK - rest_len - 1))
       messageblock[ptr++] = (rand() % (0xFF - 1)) + 1;
      messageblock[ptr++] = 0x00;
      memcpy(messageblock + ptr, message + (msg_len - rest_msg), rest_len);
      mpz_import(m, SIZE_OF_BLOCK, 1, sizeof(messageblock[0]), 0, 0, messageblock);
      mpz_powm(c,m,ke,kn);
      //offset to track positions for encrypting the cipher text   
      int off = no_of_blocks * SIZE_OF_BLOCK; 
      //pull out bytestream of ciphertext
      mpz_export(cipher + off, NULL, 1, sizeof(char), 0, 0, c);
      no_of_blocks++;
      rest_msg -= rest_len;
    }
    return no_of_blocks * SIZE_OF_BLOCK;
}

int decrypt(char* message, char* cipher, int cipherlength, mpz_t kd,mpz_t kn)
{
    int messagetracker = 0,k=2,run;
    char arraybuffer[SIZE_OF_BLOCK];
    mpz_t c; 
    mpz_init(c);
    mpz_t m; 
    mpz_init(m);
    run=cipherlength/SIZE_OF_BLOCK;
    int i;
    for( i=0 ;i < run;i++)
    {
      // convert bitstream to mpz_t to perform operations
      mpz_import(c, SIZE_OF_BLOCK, 1, sizeof(char), 0, 0, cipher + i * SIZE_OF_BLOCK);
      mpz_powm(m,c,kd,kn);
      int off = (SIZE_OF_BLOCK - (mpz_sizeinbase(m, 2) + 8 - 1)/8); 
      // Convert back to bitstream into arraybuffer using offset value at particular location
      mpz_export(arraybuffer + off, NULL, 1, sizeof(char), 0, 0, m);
      //skipping the padding and initial bits
      while((arraybuffer[k] != 0) && (k < SIZE_OF_BLOCK))
      {
       k++;
       }
      k++; // Skip the 00 byte
      memcpy(message + messagetracker, arraybuffer + k, SIZE_OF_BLOCK - k);
      messagetracker += SIZE_OF_BLOCK - k;
      
    }
    return messagetracker;
}

int main()
{

    private pri;
    public pub;

    // Initialize public key
    mpz_init(pub.n);
    mpz_init(pub.e);
    // Initialize private key
    mpz_init(pri.n);
    mpz_init(pri.e);
    mpz_init(pri.d);
    mpz_init(pri.p);
    mpz_init(pri.q);
    mpz_init(pri.dp);
   mpz_init(pri.dq);
   mpz_init(pri.Iq);

    keygeneration(&pri, &pub);

//DER ENCODER
FILE *fp1;
fp1=fopen("public.der","wb");

int at = 0x30;putc(at, fp1);
int ay=0x81;putc(ay,fp1);
int app=strlen(mpz_get_str(NULL,16,pub.n))/2+1;
int aaa=strlen(mpz_get_str(NULL,16,pub.e));
int akkr=27+app+aaa;
putc(akkr,fp1);
int ay2=0x30;putc(ay2,fp1);
int ay3=0x0d;putc(ay3,fp1);
int ay4=0x06;putc(ay4,fp1);
int ay5=0x09;putc(ay5,fp1);
int ay6=0x2a;putc(ay6,fp1);
int ay7=0x86;putc(ay7,fp1);
int ay8=0x48;putc(ay8,fp1);
putc(ay7,fp1);
int ay9=0xf7;putc(ay9,fp1);
putc(ay3,fp1);
int ay10=0x01;putc(ay10,fp1);
putc(ay10,fp1);
putc(ay10,fp1);
int ay11=0x05;putc(ay11,fp1);
int ay12=0x00;putc(ay12,fp1);
int ay13=0x03;putc(ay13,fp1);
putc(ay,fp1);
int ay14=0x8b;putc(ay14,fp1);
putc(ay12,fp1);
putc(at,fp1);
putc(ay,fp1);
int ay15=0x87;putc(ay15,fp1);
int ac=0x02;putc(ac,fp1);putc(ay,fp1);
putc(app,fp1);
putc(ay12,fp1);
char *astr = mpz_get_str(NULL, 16, pub.n);
char *aptr;
aptr=astr;
int ap,as;
for(ap=0;aptr[ap]!='\0';ap=ap+2)
{ sscanf(&aptr[ap],"%2x",&as);
putc(as, fp1);
}
putc(ac,fp1);
putc(aaa,fp1);
char *aktr = mpz_get_str(NULL,16,pub.e);
char *aztr;
aztr=aktr;
int am;
sscanf(&aztr[0],"%2x",&am);
putc(am,fp1);

fclose(fp1);
FILE *fp;
fp=fopen("private.der","wb");
//asn1 header and length
int t = 0x30;
putc(t,fp);
int py =  0x82;
putc(py,fp);
int a=strlen(mpz_get_str(NULL,16,pri.n))/2+1;
int a1=strlen(mpz_get_str(NULL,16,pri.e));
int a2=strlen(mpz_get_str(NULL,16,pri.d))/2+1;
int a3=strlen(mpz_get_str(NULL,16,pri.p))/2+1;
int a4=strlen(mpz_get_str(NULL,16,pri.q))/2+1;
int a5=strlen(mpz_get_str(NULL,16,pri.dp))/2+1;
int a6=strlen(mpz_get_str(NULL,16,pri.dq))/2+1;
int a7=strlen(mpz_get_str(NULL,16,pri.Iq))/2+1;
int k = a+a1+a2+a3+a4+a5+a6+a7+21;
int kk = k>> 8;
kk = kk & 0xff;
putc(kk,fp);
putc(k,fp); 
//algorithm version header length and string
int w=0x02;putc(w,fp);
int x=0x01;putc(x,fp);
int y=0x00;putc(y,fp);
//Modulus n value header length and string
putc(w,fp);
int uy=0x81;putc(uy,fp);
putc(a,fp);putc(y,fp);
char *str = mpz_get_str(NULL, 16, pri.n);
char *ptr;
ptr=str;
int d,p,s;

for(p=0;ptr[p]!='\0';p=p+2)
{
sscanf(&ptr[p],"%2x",&s);
putc(s, fp);
}
//e value header length and string
putc(w,fp);
putc(a1,fp);
char *ztr=mpz_get_str(NULL,16,pri.e);
char *ktr; ktr=ztr;
sscanf(&ktr[0],"%2x",&d); putc(d,fp);

//d value header length and string
putc(w,fp);putc(uy,fp);
putc(a2,fp);int s1;putc(y,fp);
char *dm=mpz_get_str(NULL,16,pri.d);
char *dd; dd=dm;
for(p=0;dd[p]!='\0';p=p+2)
{
sscanf(&dd[p],"%2x",&s1);
putc(s1,fp);
}

//prime p header length and string
putc(w,fp);putc(a3,fp);int s2;
putc(y,fp);
char *pm=mpz_get_str(NULL,16,pri.p);
char *pp;pp=pm;
for(p=0;pp[p]!='\0';p=p+2)
{
sscanf(&pp[p],"%2x",&s2);
putc(s2,fp);
}

//prime q header length and string
putc(w,fp);putc(a4,fp);int s3;
putc(y,fp);
char *qm=mpz_get_str(NULL,16,pri.q);
char *qq;qq=qm;
for(p=0;qq[p]!='\0';p=p+2)
{
sscanf(&qq[p],"%2x",&s3);
putc(s3,fp);
}
//exponent1 header length and string
putc(w,fp);putc(a5,fp);int s4;putc(y,fp);
char *gh=mpz_get_str(NULL,16,pri.dp);
char *hg;hg=gh;
for(p=0;hg[p]!='\0';p=p+2)
{
sscanf(&hg[p],"%2x",&s4);
putc(s4,fp);
}
//exponent2 header length and string
putc(w,fp);putc(a6,fp);int s5;putc(y,fp);
char *fh=mpz_get_str(NULL,16,pri.dq);
char *hf;hf=fh;
for(p=0;hf[p]!='\0';p=p+2)
{
sscanf(&hf[p],"%2x",&s5);
putc(s5,fp);
}
//coefficient header length and string
putc(w,fp);putc(a7,fp);int s6;putc(y,fp);
char *wh=mpz_get_str(NULL,16,pri.Iq);
char *hw;hw=wh;
for(p=0;hw[p]!='\0';p=p+2)
{
sscanf(&hw[p],"%2x",&s6);
putc(s6,fp);
}
fclose(fp); 
printf("\n Be sure you have:\n--> plain.txt file\n-->plain2.txt file\n-->openss_priv1024.der(openssl privatekey) previously");
printf("\nUser generated keys stored in der as:\n-->private.der\n-->public.der");
printf("\nPerform Encode and decode operations with my program generated keys??\ny or n:");
char input1[10], input2[10];
scanf("%s", input1);
printf("\n Do u want to encrypt and decrypt with openssl keys??\ny or n:");
scanf("%s", input2);
if(input1[0]=='y')
{
Encrypt_Decrypt_with_my_keys(&pri,&pub);
}

if(input2[0]=='y')
{
der_decoder();
}
 
    return 0;
}

