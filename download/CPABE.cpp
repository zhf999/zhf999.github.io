#include <iostream>
#include <pbc/pbc.h>
#include <cstring>
#include <openssl/sha.h>

// global variable
pairing_t pairing;

void cal(element_t* res,element_t a,element_t b);
void element_from_str(element_t *e,const char str[10]);

class Pubkey{
public:
    element_t g,g_b,egg_a,a;
    Pubkey()
    {
        element_t a,b,g,gb,egg,egga;
        element_init_Zr(a,pairing);
        element_init_Zr(b,pairing);
        element_init_G1(g,pairing);
        element_init_G1(gb,pairing);
        element_init_GT(egg,pairing);
        element_init_GT(egga,pairing);

        // a,b,g are random elements
        element_random(g);
        element_random(a);
        element_random(b);

        element_pow_zn(gb,g,b);
        cal(&egg,g,g);

        element_pow_zn(egga,egg,a);

        element_init_G1(this->g,pairing);
        element_init_Zr(this->a,pairing);
        element_init_G1(this->g_b,pairing);
        element_init_GT(this->egg_a,pairing);
        element_set(this->g,g);
        element_set(this->a,a);
        element_set(this->g_b,gb);
        element_set(this->egg_a,egga);
    }
};

class User
{
public:
    char attr[3][10];
    element_t hash[3];
    User(const char *attr1, const char *attr2, const char *attr3)
    {
        strcpy(attr[0],attr1);
        strcpy(attr[1],attr2);
        strcpy(attr[2],attr3);

        element_init_G1(hash[0],pairing);
        element_init_G1(hash[1],pairing);
        element_init_G1(hash[2],pairing);

        // calculating Hash values of attributes
        element_from_str(&hash[0],attr[0]);
        element_from_str(&hash[1],attr[1]);
        element_from_str(&hash[2],attr[2]);

    }
};

class SecretKey
{
public:
    element_t g_abt,gt,h_t[3];
    SecretKey(Pubkey pk, User user)
    {
        init_all();
        element_t t;
        element_init_Zr(t,pairing);
        element_random(t);

        // temp1 is a intermedia variable
        element_t temp1;
        element_init_G1(temp1,pairing);
        element_pow_zn(temp1,pk.g,pk.a);
        element_pow_zn(g_abt,pk.g_b,t);
        element_mul(g_abt,g_abt,temp1);

        element_pow_zn(gt,pk.g,t);

        element_pow_zn(h_t[0],user.hash[0],t);
        element_pow_zn(h_t[1],user.hash[1],t);
        element_pow_zn(h_t[2],user.hash[2],t);
    }

    void init_all()
    {
        element_init_G1(g_abt,pairing);
        element_init_G1(gt,pairing);
        element_init_G1(h_t[0],pairing);
        element_init_G1(h_t[1],pairing);
        element_init_G1(h_t[2],pairing);
    }
};

class SubCipher{
public:
    element_t g_bs_H,g_r;
    SubCipher()
    {

    }
    SubCipher(Pubkey pk, const char attr[10], element_t s)
    {
        init_all();
        element_t r;
        element_init_Zr(r,pairing);
        element_random(r);

        // g is from Pubkey
        element_pow_zn(g_r,pk.g,r);

        element_t H_r,H;
        element_init_G1(H_r,pairing);
        element_init_G1(H,pairing);
        element_from_str(&H,attr);

        element_pow_zn(H_r,H,r);
        element_pow_zn(g_bs_H,pk.g_b,s);
        element_mul(g_bs_H,g_bs_H,H_r);

    }

    void init_all()
    {
        element_init_G1(g_bs_H,pairing);
        element_init_G1(g_r,pairing);
    }
};

class Cipher{
public:
    element_t M_egg_as,g_s;
    SubCipher C[3];
    Cipher(Pubkey pk, element_t M) {
        element_t s[3],ss,r;
        element_init_Zr(ss,pairing);
        element_init_Zr(r,pairing);
        element_init_Zr(s[0],pairing);
        element_init_Zr(s[1],pairing);
        element_init_Zr(s[2],pairing);
        element_init_GT(M_egg_as,pairing);
        element_init_G1(g_s,pairing);

        element_random(ss);
        element_random(r);

        element_set(s[0],ss);
        element_set(s[1],r);
        element_sub(s[2],ss,r);


        C[0] = SubCipher(pk,"Prof",s[0]);
        C[1] = SubCipher(pk,"CS",s[1]);
        C[2] = SubCipher(pk,"Teacher",s[2]);

        element_pow_zn(g_s,pk.g,ss);

        element_pow_zn(M_egg_as,pk.egg_a,ss);
        element_mul(M_egg_as,M_egg_as,M);
    }
};

void Decrypt(Cipher cipher,SecretKey secretKey,element_t *res1,element_t *res2);
void together(Cipher cipher,SecretKey secretKey1,SecretKey secretKey2,element_t *res);

int main() {
    char param[1024];
    FILE *fp = fopen("a.param","r");
    size_t count = fread(param,1,1024,fp);
    if(!count )pbc_die("input error!");
    pairing_init_set_buf(pairing,param,1024);

    Pubkey pk;
    User Alice("Master","CS","Assistant"),
    Bob("Prof","EE","Teacher");


    SecretKey Sa(pk,Alice),Sb(pk,Bob);

    element_t M;
    element_init_GT(M,pairing);
    element_random(M);
    element_printf("M:%B\n\n",M);
    Cipher cipher(pk,M);

    element_t res1,res2;
    element_init_GT(res1,pairing);
    element_init_GT(res2,pairing);

    Decrypt(cipher,Sa,&res1,&res2);
    element_printf("Alice1:%B\n",res1);
    element_printf("Alice2:%B\n",res2);
    if(0==(element_cmp(res1,M))||
       0==(element_cmp(res2,M)))
        printf("Alice decrypt successfully!\n");
    else  printf("Alice fail!\n");


    Decrypt(cipher,Sb,&res1,&res2);
    element_printf("Bob1:%B\n",res1);
    element_printf("Bob2:%B\n",res2);
    if(0==(element_cmp(res1,M))||
       0==(element_cmp(res2,M)))
        printf("Bob decrypt successfully!\n");
    else  printf("Bob fail!\n");

    element_t res;
    element_init_GT(res,pairing);
    together(cipher,Sa,Sb,&res);

    element_printf("Together:%B\n",res);
    if(0==(element_cmp(res,M)))
        printf("Together successfully!\n");
    else printf("Together fail!\n");

    return 0;
}


void cal(element_t* res,element_t a,element_t b)
{
    element_init_GT(*res,pairing);
    pairing_pp_t temp;
    pairing_pp_init(temp,a,pairing);
    pairing_pp_apply(*res,b,temp);
}

void element_from_str(element_t *e,const char str[10])
{
    unsigned char buf[20];
    SHA1((unsigned char *)str,strlen(str),buf);
    element_from_hash(*e,buf,20);
}

void Decrypt(Cipher cipher,SecretKey secretKey,element_t *res1,element_t *res2)
{

    element_t egg_bts,fm,fz;
    element_init_GT(egg_bts,pairing);
    element_init_GT(fz,pairing);
    element_init_GT(fm,pairing);

    cal(&fz,cipher.C[0].g_bs_H,secretKey.gt);
    cal(&fm,secretKey.h_t[0],cipher.C[0].g_r);

    element_div(egg_bts,fz,fm);

    element_t e_gs_gabt;
    element_init_GT(e_gs_gabt,pairing);
    cal(&e_gs_gabt,cipher.g_s,secretKey.g_abt);

    element_t egg_as;
    element_init_GT(egg_as,pairing);
    element_div(egg_as,e_gs_gabt,egg_bts);

    element_div(*res1,cipher.M_egg_as,egg_as);

    element_t fs1,fs2,fz1,fz2,fm1,fm2;
    element_init_GT(fs1,pairing);
    element_init_GT(fs2,pairing);
    element_init_GT(fz1,pairing);
    element_init_GT(fz2,pairing);
    element_init_GT(fm1,pairing);
    element_init_GT(fm2,pairing);

    cal(&fz1,cipher.C[1].g_bs_H,secretKey.gt);
    cal(&fm1,secretKey.h_t[1],cipher.C[1].g_r);
    cal(&fz2,cipher.C[2].g_bs_H,secretKey.gt);
    cal(&fm2,secretKey.h_t[2],cipher.C[2].g_r);
    element_div(fs1,fz1,fm1);
    element_div(fs2,fz2,fm2);
    element_mul(egg_bts,fs1,fs2);
    element_div(egg_as,e_gs_gabt,egg_bts);
    element_div(*res2,cipher.M_egg_as,egg_as);

}

void together(Cipher cipher,SecretKey secretKey1,SecretKey secretKey2,element_t *res)
{
    element_t egg_bts;
    element_init_GT(egg_bts,pairing);
    element_t e_gs_gabt;
    element_init_GT(e_gs_gabt,pairing);
    cal(&e_gs_gabt,cipher.g_s,secretKey1.g_abt);

    element_t egg_as;
    element_init_GT(egg_as,pairing);
    element_div(egg_as,e_gs_gabt,egg_bts);

    element_t fs1,fs2,fz1,fz2,fm1,fm2;
    element_init_GT(fs1,pairing);
    element_init_GT(fs2,pairing);
    element_init_GT(fz1,pairing);
    element_init_GT(fz2,pairing);
    element_init_GT(fm1,pairing);
    element_init_GT(fm2,pairing);

    cal(&fz1,cipher.C[1].g_bs_H,secretKey1.gt);
    cal(&fm1,secretKey1.h_t[1],cipher.C[1].g_r);
    cal(&fz2,cipher.C[2].g_bs_H,secretKey2.gt);
    cal(&fm2,secretKey2.h_t[2],cipher.C[2].g_r);
    element_div(fs1,fz1,fm1);
    element_div(fs2,fz2,fm2);
    element_mul(egg_bts,fs1,fs2);
    element_div(egg_as,e_gs_gabt,egg_bts);
    element_div(*res,cipher.M_egg_as,egg_as);
}
