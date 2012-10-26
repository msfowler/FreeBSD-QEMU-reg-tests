#include <string.h>
#include <stdio.h>

int main(int argc, char * argv[])
{
	if(argc != 2)
	{
		return -1;
	}

	if(strcmp(argv[1], "word")!= 0)
	{ 
		return -1;
	}
	else
	{
		return 123;
	}
}
