#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/aes.h>

#define PORT 5001

int connection_setup(void);
int connect_to_server(void);

int main(void)
{
	int listenfd ,clientfd ,serverfd;
	int n, size;
	char *a1, *a2;//for temp usage
	char *aeskey, *plaintext;
	char student_num[7]  = "0356539";
	unsigned char iniv[16] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	unsigned char iniv2[16] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	unsigned char iniv3[16] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	char recebuff[1024] ,sendbuff[1024];
	RSA *myrsakey = RSA_new();
	RSA *serrsakey = RSA_new();
	AES_KEY myaes;
	AES_KEY seraes;
	AES_KEY aes3;
	BIGNUM *mye;

	listenfd = connection_setup();
	if(listenfd == 0)
		return 0;
	if((clientfd = accept(listenfd,(struct sockaddr*)NULL,NULL)) < 0)
	{
		printf("connect() call error\n");
		return 0;
	}
	serverfd = connect_to_server();
	if(serverfd == 0)
		return 0;
//=============================================================
//hello phase
	bzero(sendbuff,sizeof(sendbuff));
	bzero(recebuff,sizeof(recebuff));

	n=read(clientfd,recebuff,sizeof(recebuff));
	memcpy(&size,recebuff,4);
	printf("receive from client %dbytes\n",n);
	printf("content size is %d\n",size);
	write(serverfd,recebuff,n);
//=============================================================
//server phase 1
	bzero(sendbuff,sizeof(sendbuff));
	bzero(recebuff,sizeof(recebuff));

	n=read(serverfd,recebuff,sizeof(recebuff));
	memcpy(&size,recebuff,4);
	printf("receive from server %dbytes\n",n);
	printf("content size is %d\n",size);

	a1 = (char*)malloc(size);
	memcpy(a1,recebuff+4,size);
	serrsakey->n = BN_new();
	BN_bin2bn(a1,size,serrsakey->n);
	//free(a1);
	printf("server RSA size = %d\n",RSA_size(serrsakey));

	bzero(sendbuff,sizeof(sendbuff));
	bzero(recebuff,sizeof(recebuff));

	n=read(serverfd,recebuff,sizeof(recebuff));
	memcpy(&size,recebuff,4);
	printf("receive from server %dbytes\n",n);
	printf("content size is %d\n",size);

	a1 = (char*)malloc(size);
	memcpy(a1,recebuff+4,size);
	serrsakey->e = BN_new();
	BN_bin2bn(a1,size,serrsakey->e);
	//free(a1);
//=============================================================
//client phase 1
	bzero(sendbuff,sizeof(sendbuff));
	bzero(recebuff,sizeof(recebuff));

	mye = BN_new();
	BN_set_word(mye,RSA_F4);
	RSA_generate_key_ex(myrsakey, 1024 ,mye ,NULL);

	size = BN_num_bytes(myrsakey->n);//why must use malloc,why can't BN_bn2bin(myrsakey->n,sendbuff+4)?;
	memcpy(sendbuff,&size,4);
	a1 = (char*)malloc(size);
	BN_bn2bin(myrsakey->n,a1);
	memcpy(sendbuff+4,a1,size);
	n=write(clientfd,sendbuff,size+4);
	free(a1);

	bzero(sendbuff,sizeof(sendbuff));
	bzero(recebuff,sizeof(recebuff));

	size = BN_num_bytes(myrsakey->e);
	memcpy(sendbuff,&size,4);
	a1 = (char*)malloc(size);
	BN_bn2bin(myrsakey->e,a1);
	memcpy(sendbuff+4,a1,size);
	n=write(clientfd,sendbuff,size+4);
	free(a1);
//=============================================================
//client phase 2
	bzero(sendbuff,sizeof(sendbuff));
	bzero(recebuff,sizeof(recebuff));

	n=read(clientfd,recebuff,sizeof(recebuff));
	printf("receive from client %dbytes\n",n);

	aeskey = (char*)malloc(128);
	n=RSA_private_decrypt(128, recebuff+4, aeskey,myrsakey, RSA_PKCS1_OAEP_PADDING);
	printf("aes decrypt size = %d\n",n);
	n=AES_set_decrypt_key(aeskey,128, &myaes);
	n=AES_set_encrypt_key(aeskey,128, &seraes);
	n=AES_set_decrypt_key(aeskey,128, &aes3);

	bzero(sendbuff,sizeof(sendbuff));
	bzero(recebuff,sizeof(recebuff));

	n=read(clientfd,recebuff,sizeof(recebuff));
	printf("receive from client %dbytes\n",n);

	plaintext = (char*)malloc(48);
	AES_cbc_encrypt(recebuff+4, plaintext, 48, &myaes, iniv, AES_DECRYPT);
	//plaintext[30] = 0;
	printf("plain text length = %d\n",strlen(plaintext));
	printf("plain text = %s\n",plaintext);
	memcpy(plaintext,student_num,sizeof(student_num));
	printf("plain text = %s\n",plaintext);
//=============================================================
//server phase 2
	bzero(sendbuff,sizeof(sendbuff));
	bzero(recebuff,sizeof(recebuff));

	a1 = (char*)malloc(128);
	n=RSA_public_encrypt(16, aeskey, a1, serrsakey, RSA_PKCS1_OAEP_PADDING);
	printf("RSA return = %d\n",n);
	size = 128;
	memcpy(sendbuff,&size,4);
	memcpy(sendbuff+4,a1,size);
	n=write(serverfd,sendbuff,size+4);
	printf("%d bytes sended\n",n);
	free(a1);
	free(aeskey);

	bzero(sendbuff,sizeof(sendbuff));
	bzero(recebuff,sizeof(recebuff));

	a1 = (char*)malloc(48);
	AES_cbc_encrypt(plaintext, a1, 30, &seraes, iniv2, AES_ENCRYPT);
	size = 48;
	memcpy(sendbuff,&size,4);
	memcpy(sendbuff+4,a1,size);
	n=write(serverfd,sendbuff,size+4);
	printf("%d bytes sended\n",n);
/*
	a2 = (char*)malloc(48);
	AES_cbc_encrypt(a1, a2, 48, &aes3, iniv3, AES_DECRYPT);
	printf("%s\n",a2);

	free(a2);
*/
	free(a1);
	free(plaintext);

	return 0;
}

int connection_setup(void)
{
	int fd;
	struct sockaddr_in serv_addr;

	if((fd = socket(AF_INET , SOCK_STREAM , 0)) < 0)
	{
		printf("socket() call error\n");
		return 0;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(PORT);

	if(bind(fd , (struct sockaddr *) &serv_addr , sizeof(serv_addr)) < 0)
	{
		printf("bind() call error\n");
		return 0;
	}
	if(listen(fd,1) < 0)
	{
		printf("listen() call error\n");
		return 0;
	}
	return fd;
}

int connect_to_server(void)
{
	int sockfd;
	struct sockaddr_in serv_addr;

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0))< 0)
	{
		printf("\n Error : Could not create socket \n");
		return 0;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(8889);
	serv_addr.sin_addr.s_addr = inet_addr("140.113.216.178");

	if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))<0)
	{
		printf("\n Error : Connect Failed \n");
		return 0;
	}
	return sockfd;
}
