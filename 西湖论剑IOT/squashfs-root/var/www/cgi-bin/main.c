#include<stdio.h>
#include<stdlib.h>

int main(){
	setenv("HTTP_COOKIES","uuid=%7$p",1);
	printf("HTTP_COOKIES=%s\n", getenv("HTTP_COOKIES"));
	return 0;
}
