#include <string>
#include <iostream>
#include "DES.h"
// #include <chrono>

using namespace std;

int main() {

    string plaintext = "0123456789ABCDEF";
    string key = "133457799BBCDFF1";
    DES* des = new DES;

    // auto start = chrono::high_resolution_clock::now();
    string ciphertext = des->encrypt(key, plaintext);
    // auto stop = chrono::high_resolution_clock::now();
    // auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);

    cout << endl;
    cout << "plaintext: " << plaintext << endl;
    cout << "key: " << key << endl;
    cout << "ciphertext: " << ciphertext << endl << endl;
    // cout << "time: " << duration.count() << " microseconds" << endl << endl;

    plaintext = "123456ABCD132536";
    key = "AABB09182736CCDD";
    ciphertext = des->encrypt(key, plaintext);

    cout << "plaintext: " << plaintext << endl;
    cout << "key: " << key << endl;
    cout << "ciphertext: " << ciphertext << endl << endl;

    return 0;

}
