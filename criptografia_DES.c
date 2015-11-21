/*  Universidade Federal de São Carlos - Campus Sorocaba
 *  Bacharelado em Ciencia da Computacao
 * 	 
 *  Disciplina: Introducao a Criptografia
 *  Prof Doutora Yeda Regina Venturini 
 *  Aluno: Rafael D. Santos Ra: 408654
 * 
 * 	Descricao: Uma implementacao do Algoritmo de Criptografia DES.
 *	Observacoes: Infelizmente essa implementacao so funciona em computadores de arquitetura de 64 bits
 *  quando percebi, era tarde de mais para mudar a abordagem =/.
 *  Entrada: Hexadecimal.
 *  Saida: Hexadecimal.
 *  
 * Created on 3 de Abril de 2015, 17:40
 */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

int DEBUG = 1; //exibe os prints de cada etapa do DES
int MODO_AUTOMATICO = 1; //usa os casos de testes de exemplo disponibilizado no Moodle
int TUTORIAL = 1; //revela um tutorial no final de como usar esse programa
//, caso seja zero recebe o plaintext e a chave em hexa como entrada pelo terminal.

unsigned long int DESLOCA[16];
unsigned long int PCI2[16];
unsigned long int chave;
int IP [64]    = { 58, 50, 42, 34, 26, 18, 10, 2,
                    60, 52, 44, 36, 28, 20, 12, 4,
                    62, 54, 46, 38, 30, 22, 14, 6,
                    64, 56, 48, 40, 32, 24, 16, 8,
                    57, 49, 41, 33, 25, 17, 9,  1,
                    59, 51, 43, 35, 27, 19, 11, 3,
                    61, 53, 45, 37, 29, 21, 13, 5,
                    63, 55, 47, 39, 31, 23, 15, 7};

int IP_INVERSO [64]    = {  40,  8, 48, 16, 56, 24, 64, 32,
                        	39,  7, 47, 15, 55, 23, 63, 31,
                        	38,  6, 46, 14, 54, 22, 62, 30,
                       		37,  5, 45, 13, 53, 21, 61, 29,
                        	36,  4, 44, 12, 52, 20, 60, 28,
                        	35,  3, 43, 11, 51, 19, 59, 27,
                        	34,  2, 42, 10, 50, 18, 58, 26,
                        	33,  1, 41,  9, 49, 17, 57, 25};



int PC1[56] = {57, 49, 41, 33, 25, 17, 9,
                             1, 58, 50, 42, 34, 26, 18,
                             10, 2, 59, 51, 43, 35, 27,
                             19, 11, 3, 60, 52, 44, 36,
                             63, 55, 47, 39, 31, 23, 15,
                             7, 62, 54, 46, 38, 30, 22,
                             14, 6, 61, 53, 45, 37, 29,
                             21, 13, 5, 28, 20, 12, 4};

int PC2[48] = {14, 17, 11, 24,  1,  5,  3, 28,
                             15,  6, 21, 10, 23, 19, 12,  4,
                             26,  8, 16,  7, 27, 20, 13,  2,
                             41, 52, 31, 37, 47, 55, 30, 40,
                             51, 45, 33, 48, 44, 49, 39, 56,
                             34, 53, 46, 42, 50, 36, 29, 32};

 int E[48] ={ 32,  1,  2,  3,  4,  5,
                            4,  5,  6,  7,  8,  9,
                            8,  9, 10, 11, 12, 13,
                            12, 13, 14, 15, 16, 17,
                            16, 17, 18, 19, 20, 21,
                            20, 21, 22, 23, 24, 25,
                            24, 25, 26, 27, 28, 29,
                            28, 29, 30, 31, 32,  1};

 int P[32] = {16, 7, 20, 21, 29, 12, 28, 17,
                            1, 15, 23, 26, 5, 18, 31, 10,
                            2, 8, 24, 14, 32, 27, 3, 9,
                            19, 13, 30, 6, 22, 11, 4, 25};


int caixa_S[8][4][16] ={
    //S1
                    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
    //S2
                    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
    //S3
                    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
     //S4
                   {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                    1, 5, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
      //S5
                    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},

//S6
                    {12, 1, 10, 15,  9,  2, 6,  8,  0, 13,  3, 4, 14, 7,  5, 11,
                    10, 15,  4, 2,  7, 12, 9,  5,  6,  1, 13, 14, 0, 11, 3,  8,
                    9,  14, 15, 5,  2,  8, 12, 3,  7,  0,  4, 10, 1, 13, 11, 6,
                    4,   3,  2, 12, 9,  5, 15, 10, 11, 14, 1,  7, 6,  0,  8, 13},
//S7
                    { 4, 11,  2, 14, 15, 0,  8, 13,  3, 12, 9,  7, 5, 10, 6,  1,
                    13,  0, 11,  7,  4, 9,  1, 10, 14,  3, 5, 12, 2, 15, 8,  6,
                     1,  4, 11, 13, 12, 3,  7, 14, 10, 15, 6,  8, 0,  5, 9,  2,
                     6, 11, 13,  8,  1, 4, 10,  7,  9,  5, 0, 15, 14, 2, 3, 12},
//S7
                    {13,  2,  8, 4,  6, 15,  11,  1, 10, 9,  3, 14,  5,  0, 12, 7,
                    1, 15, 13, 8, 10,  3,   7,  4, 12, 5,  6, 11,  0, 14,  9, 2,
                    7, 11,  4, 1,  9,  12, 14,  2, 0,  6, 10, 13, 15,  3,  5, 8,
                    2,  1, 14, 7,  4,  10,  8, 13, 15, 12, 9,  0,  3,  5,  6, 11}

};

unsigned long int indice(long n){
    unsigned long int i=1;
    return i << n;
}

//permutacao generica
unsigned long int permutacao_g(unsigned long int num, int v[],int tam,int tam2){
    unsigned long int i,j, saida = 0;
    for(i=0,j=tam-1;i<tam;i++,j--){
        if(num & indice(tam2 - v[i])){
                saida |= indice(j);
        }
    }
    return saida;
}

int shift28(int num, int tam){
    int i,d;
    for(i=0;i<tam;i++){
        d = num << 1;
        if(d & 0x10000000){
            d++;
            d -= 0x10000000; 
        }
		num = d;
    }
    return d;
}

unsigned long int* gera_chave(unsigned long int chave){
    unsigned long int L=0, R=0,C,D;
    unsigned long int *KN = (unsigned long int *) malloc(sizeof(unsigned long int)*16);
	
    unsigned long int chaveg = permutacao_g(chave,PC1,56,64);//certo
	if(DEBUG) printf("PC1: %lX\n",chaveg);
    int escala [16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
	
    L = 0x0fffffff0000000 & chaveg;
    R = 0x0fffffff & chaveg;
	
    int i=0;
	
	unsigned long int tR = R, tL =L;
    for(i=0;i<16;i++){
        C = shift28(tR, escala[i]);
        D = shift28(tL >> 28, escala[i]);
		D = D << 28;
		tR = C;
		tL = D;
        unsigned long int temp = C | D;
		//essa variavel global magica serve para dar print do deslocamento no lugar certo 
		DESLOCA[i] = temp;
        KN[i] = permutacao_g(temp,PC2, 48,56);
		
    }
    
    return KN;
} 
//calcula o primeiro indice da SBOX, cuidado pode conter binarios!
int indiceSBOX_1 (unsigned long int x) {
	int id1 = 0;	
	if(0B100000 & x) id1 |= 0B10;
	if(0B000001 & x) id1 |= 0B01;
	return id1;
}
//calcula o segundo indice da SBOX
int indiceSBOX_2 (unsigned long int x) {
	int id2 = 0;	
	id2 = x & 0B011110;
	return id2 >> 1;
}

unsigned long int encriptar(unsigned long int bloco){
    unsigned long int L=0, R=0, *KN;
    KN = gera_chave(chave);
    
    bloco = permutacao_g(bloco,IP,64,64);
	if(DEBUG) printf("IP: %lX\n\n",bloco);
    R = bloco & 0xffffffff;
    L = bloco & 0xffffffff00000000;
	
    
    //rodadas
    int i,j;
	unsigned long int tempL=L, tempR=R;
    for(i=0;i<16;i++){        
		unsigned long int tempE;
		tempL=L, tempR=R;
		if(DEBUG) printf("CHAVE DE ROUND %d\nDeslocamento: %lX\nPC2: %lX\n\n",i+1,DESLOCA[i],KN[i]);        
		if(DEBUG) printf("ROUND %d\n",i+1);
        
		//funcao F
        tempE = permutacao_g(tempR, E, 48, 32);		
		if(DEBUG) printf("Expancao: %lX\n",tempE);
        R = KN[i] ^ tempE; //são 48 bits! Esquecer isso pode ser critico
		if(DEBUG) printf("Add Key: %lX\n",R);
        int sbox = 0;
		//caixa S - funcionado :D
		unsigned long int tR = R,n;
        for(j=0,n=7;j<8;j++,n--){
			tR = R;// << 6*j;
			unsigned long int magic_num = 0x3f; 
            unsigned long int temp = tR &(magic_num << 42-j*6);	
			int aux = caixa_S[j][indiceSBOX_1(temp>>(42-j*6))][indiceSBOX_2(temp>>(42-j*6))];
			      
			sbox |= aux << 28-j*4;
			
			R = tR;
        }
		
		if(DEBUG) printf("S-Box: %X\n",sbox);
		unsigned long int permuta;
		permuta = permutacao_g(sbox,P,32,32);
		if(DEBUG) printf("Permuta: %lX\n",permuta);		        
		if(DEBUG) printf("temp R - %lX\n", tempR);
		L = tempR;
		if(i == 0) tempL = tempL >>32;
        R = permuta ^ tempL;

		if(DEBUG) printf("Add Left: %lX\n\n",R);
    }
    //swap
	unsigned long int swap = (R<<32) | L;
    if(DEBUG) printf("swap: %lX\n\n",swap);
    
	unsigned long int result = permutacao_g(swap,IP_INVERSO,64,64);
	printf("RESULT: %lX\n",result);
    free(KN);
	return result;
}



int main(int argc, char** argv) {
	unsigned long int bloco;//plain text	
	if(MODO_AUTOMATICO){
		bloco = 0x675A69675E5A6B5A;
		chave = 0x3132333435363738;
    } else{
		printf("Informe o plain text(hexa)>\n");
		scanf("%lx", &bloco);
		printf("Nao esqueca de digitar a chave tambem(hexa)>\n");
		scanf("%lx", &chave);
	}
	if(DEBUG) printf("Chave: %lX\n",chave);
	if(DEBUG) printf("Plaintext: %lX\n",bloco);
	encriptar(bloco);
	if(TUTORIAL) printf("\nCaso voce queira usar sua entrada nesse programa modifique a variavel MODO_AUTOMATICO para zero\n");
	if(TUTORIAL) printf("Obrigado por criptografar conosco!\n");
    return 0;
}

