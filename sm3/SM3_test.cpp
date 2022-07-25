
// SM3_test.cpp : 
// 测试两种哈希函数碰撞方法 1. naive birthday attack 2. Rho method 
// 测试针对 SM3 的 length extension attack；
#define Target_Collision_Bits 16 // 由于算力有限，只对SM3的高位进行哈希碰撞测试 (当该值设为 64 时，Birthday attack 内存占用会大幅增加，该值不应该超过64, 当该值设为 32 时，Rho attack 要比较上万次时时间复杂度会非常的高，非常耗时；) ；
#define Target_Collision_Bytes Target_Collision_Bits/8
#define Input_MSG 4374 // 设置 collision detection 的一个起始消息值；


typedef struct {
    size_t A; // 一个SM3摘要的最高64位（8B）
    size_t B; // 次高64位
    size_t C; // 以此类推...
    size_t D; // 最低64位
} Digest_Instance;

#include <iostream>
#include"sm3/sm3.h"
#include<unordered_map>
#include<string>
#include<utility>
#include<list>
#include<iterator>
#include<iomanip>
#include<stdio.h>

using std::unordered_map;
using std::string;
using std::pair;
using std::cout;
using std::endl;
using std::list;

void Birthday_Attack();
void Uchar_to_ULL(const unsigned char* md, size_t& s);
void Rho_Attack();
list<Digest_Instance>::iterator List_Search(list<Digest_Instance>& track, const Digest_Instance& target);
void show_Digest(const Digest_Instance& target);
void Uchar_to_Digest(const unsigned char* md, Digest_Instance& s);
void Length_Extension_Attack();

int main()
{


    //Birthday_Attack();
    //Rho_Attack();
    Length_Extension_Attack();

}

void Birthday_Attack()
{
    cout << "Birthday attack test..."<<endl;
    unsigned char md[SM3_DIGEST_LENGTH] = { 0 };

    SM3_CTX test;
    size_t i;
    bool collision = false;
    unordered_map<size_t, size_t> hash;
    size_t subs = 0;

    cout << "Collision detection will begin at message " << Input_MSG << endl;

    for (i = Input_MSG;; i++)
    {
        ossl_sm3_init(&test);
        ossl_sm3_update(&test, &i, sizeof(size_t));
        ossl_sm3_final(md, &test);
        Uchar_to_ULL(md, subs);
        if (hash.find(subs) == hash.end()) {
            hash.insert(pair<size_t, size_t>(subs, i));
        }
        else { collision = true; break; }

    }

    cout << "collison occurs after " << i - Input_MSG << " tries,on " << Target_Collision_Bits << " most significant bits : ";
    for (int j = 0; j < Target_Collision_Bytes; j++)
        printf("%02x", *(md + j));
    cout << " between message " << i << " and " << hash[subs];

    cout << endl << "where" << endl << "message " << hash[subs] << " has digest：";
    ossl_sm3_init(&test);
    ossl_sm3_update(&test, &(hash[subs]), sizeof(size_t));
    ossl_sm3_final(md, &test);
    for (int j = 0; j < SM3_DIGEST_LENGTH; j++)
        printf("%02x", *(md + j));

    cout << endl << "message " << i << " has digest：";
    ossl_sm3_init(&test);
    ossl_sm3_update(&test, &i, sizeof(size_t));
    ossl_sm3_final(md, &test);
    for (int j = 0; j < SM3_DIGEST_LENGTH; j++)
        printf("%02x", *(md + j));
}

void Rho_Attack()
{
    cout <<endl<< "Rho Method Collision test..."<<endl;
    unsigned char md[SM3_DIGEST_LENGTH] = { 0 };
    list<Digest_Instance> track;
    SM3_CTX test;
    Digest_Instance start;
    start.D = Input_MSG;
    bool collision = false;
    track.push_back(start);
    Digest_Instance next;
    size_t count = 0;

    while (!collision) {
        count++;
        ossl_sm3_init(&test);
        ossl_sm3_update(&test, &(track.back()), sizeof(Digest_Instance));
        ossl_sm3_final(md, &test);
        Uchar_to_Digest(md, next);
        auto rslt = List_Search(track, next);
        if (rslt != track.end())
        {
            collision = true;
            cout << "Collision occurs after " << count << " tries, on " << Target_Collision_Bits << " most significant bits ";
            cout << endl << "between message ";
            show_Digest(track.back());
            cout << endl << "with digest:";
            show_Digest(next);
            cout << endl << "and message ";
            rslt--;
            show_Digest(*rslt); 
            rslt++;
            cout << endl << "with digest:";
            show_Digest(*(rslt));

        }
        else
            track.push_back(next);

    }


}

void Length_Extension_Attack()
{
    // 已知 消息 “secretdata”的摘要，目标是要得到字符串“append”拼接到“secretdata”（padding以后）后计算得到的摘要值，即已知 H(secretdata(已padding)),求 H(secretdata(已padding)||append)
    // 1.模拟攻击者获取到了 H(secretdata(已padding))：
    cout << endl << "1.模拟攻击者获取到了 H(secretdata(已padding))：" << endl;
    unsigned char md[SM3_DIGEST_LENGTH];
    SM3_CTX c1;
    ossl_sm3_init(&c1);
    ossl_sm3_update(&c1, "secretdata", 10);
    ossl_sm3_final(md, &c1);
    for (int i = 0; i < SM3_DIGEST_LENGTH; i++) {
        printf("%02x", md[i]);
    }
    printf("\n");


    // 2.模拟攻击者计算H(secretdata(已padding)||append)
    cout << " 2.模拟攻击者计算H(secretdata(已padding)||append)"<<endl;
    SM3_CTX c2;
    ossl_sm3_init(&c2);
    ossl_sm3_update(&c2, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 64);
    c2.A = c1.A;
    c2.B = c1.B;
    c2.C = c1.C;
    c2.D = c1.D;
    c2.E = c1.E;
    c2.F = c1.F;
    c2.G = c1.G;
    c2.H = c1.H;
    ossl_sm3_update(&c2, "append", 6);
    ossl_sm3_final(md, &c2);
    for (int i = 0; i < SM3_DIGEST_LENGTH; i++) {
        printf("%02x", md[i]);
    }
    printf("\n");


    // 3.验证攻击者的计算正确性：
    cout << "3.验证攻击者的计算正确性：" << endl;
    SM3_CTX c3;
    ossl_sm3_init(&c3);
    ossl_sm3_update(&c3, 
        "secretdata"
        "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x50"
        "append", 70);
    ossl_sm3_final(md,&c3);
    for (int i = 0; i < SM3_DIGEST_LENGTH; i++) {
        printf("%02x", md[i]);
    }
    printf("\n");
}


void Uchar_to_ULL( const unsigned char* md, size_t& s)
{
    s = 0;
    for (int j = 0; j < sizeof(size_t) / sizeof(unsigned char) && j < Target_Collision_Bytes / sizeof(unsigned char); j++)
    {
        s = s << 8;
        s |= md[j];
    }
}

void Uchar_to_Digest(const unsigned char* md, Digest_Instance& s)
{
    s.A = s.B = s.C = s.D = 0;
    for (int j = 0; j < SM3_DIGEST_LENGTH; j++)
    {
        if (j < 8) {
            s.A = s.A << 8;
            s.A |= md[j];
        }
        else if (j < 16) {
            s.B = s.B << 8;
            s.B |= md[j];
        }
        else if (j < 24) {
            s.C = s.C << 8;
            s.C |= md[j];
        }
        else {
            s.D = s.D << 8;
            s.D |= md[j];
        }
    }
}

list<Digest_Instance>::iterator List_Search(list<Digest_Instance>& track,const Digest_Instance& target)
{
    auto current = track.begin();
    size_t rslt=0;

    while (current!=track.end())
    {
        if (Target_Collision_Bytes <= 8)
        {
            rslt = ((*current).A ^ target.A)>>(64-Target_Collision_Bytes*8);
        }
        if (rslt != 0)
            current++;
        else
            break;
    }
    return current;
    
}

void show_Digest(const Digest_Instance& target)
{
    cout << std::setbase(16) << target.A << " - " << target.B << " - " << target.C << " - " << target.D << std::setbase(10);
}














