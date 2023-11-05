#include<cstdio>
#include<cstring>
#include<iostream>

class Foo
{

public:
    char *str;
    Foo(const char *s)
    {
        int len = strlen(s);
        str = new char[len+1];
        strcpy(str,s);
        printf("Constructor\n");
    }
    
    ~Foo()
    {
        delete[] str;
        printf("Destructor\n");
    }
};

Foo getFoo(const char *s)
{
    return Foo(s);
}

int main()
{
    Foo a = getFoo("Hello");
    printf("%s\n",a.str);
}