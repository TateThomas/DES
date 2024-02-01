#ifndef DES_H
#define DES_H

#include <string>
#include <sstream>
#include <cstdint>
#include <iomanip>

using namespace std;

class DES {
    
    public:

        string encrypt(const string key, const string message) {

            unsigned long long int roundKey, bits, IPBits, left, right, rightCopy, finalBits;

            // prepare message and ciphertext
            const string paddedMessage = message + string(message.length() % (this->BLOCK_SIZE / 4), '0');    // pad message with 0s to make the size a multiple of 64
            string ciphertext = "";

            roundKey = this->permutedChoice1(stoull(key, NULL, 16));   // prepare key

            // loop through message blocks (size 64 bits)
            for (int i = 0; i < (paddedMessage.length() / (this->BLOCK_SIZE / 4)); i++) {

                bits = stoull(paddedMessage.substr(this->BLOCK_SIZE * i, (this->BLOCK_SIZE * (i + 1)) - 1), NULL, 16);  // extract submessage, convert to bits
                IPBits = this->initialPermutation(bits);
                
                // split into left and right (long long necessary to prevent loss of data via overflow)
                left = (IPBits & ((((uint64_t)1 << 32) - 1) << 32)) >> 32;
                right = IPBits & (((uint64_t)1 << 32) - 1);
                rightCopy;

                // 16 round Feistel network
                for (int i = 0; i < this->ROUNDS; i++) {

                    roundKey = this->rotateBits(roundKey, this->leftShiftMatrix[i]);
                    rightCopy = right;
                    right = left ^ this->fFunction(this->permutedChoice2(roundKey), right);
                    left = rightCopy;

                }

                // convert back to hex string and add it to the final ciphertext
                finalBits = this->finalPermutation((right << 32) | left);
                stringstream stream;
                stream << setfill('0') << setw(sizeof(finalBits)*2) << hex << finalBits;
                ciphertext = ciphertext + stream.str();

            }

            return ciphertext;

        }

        string decrypt(string key, string ciphertext) {

            return "0";

        }
    
    private:

        int BLOCK_SIZE = 64;
        int ROUNDS = 16;

        int IPMatrix[64] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
        int IPInverseMatrix[64] = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 26, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};
        int PC1Matrix[56] = {57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};
        int PC2Matrix[48] = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
        int expansionMatrix[48] = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
        int sBoxes[8][4][16] = {
            {
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            {
                {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            {
                {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
            },
            {
                {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            },
            {
                {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
            {
                {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
            },
            {
                {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
            {
                {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }
        };
        int permutationMatrix[32] = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};
        int leftShiftMatrix[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};


        unsigned long long int permutate(const unsigned long long int bits, const int matrix[], const int inputSize, const int outputSize) {
            /* 
                Permutates a given set of bits (integer) using a matrix tranformation (array containing new locations for each bit).
                Requires a specified input size and output size in bits.
            */

            unsigned long long int permutatedBits = 0;
            int bitLocation, extractedBit;

            for (int i = 0; i < outputSize; i++) {

                bitLocation = inputSize - matrix[i];
                extractedBit = (((uint64_t)1 << bitLocation) & bits) >> bitLocation;
                permutatedBits = permutatedBits | ((uint64_t)extractedBit << (outputSize - 1 - i));

            }

            return permutatedBits;

        }

        unsigned long long int rotateBits(const unsigned long long int bits, const int nLeftShifts) {
            /*
                Rotates the left and right halves of a 64 bit integer to the left a specified amount of times. Left overflow for each half
                will be placed at the right of the that half.
            */

            unsigned long long int bitBlock, finalBits;
            unsigned int extractedBits;

            finalBits = 0;

            for (int i = 0; i < 2; i++) {

                bitBlock = (((((uint64_t)1 << 28) - 1) << (28 * (1 - i))) & bits) >> (28 * (1 - i));    // extract left/right blocks
                extractedBits = ((uint64_t)((nLeftShifts * 2) - 1) << (28 - nLeftShifts)) & bitBlock;   // extract overflow bits
                finalBits = finalBits | ((((bitBlock ^ extractedBits) << nLeftShifts) | (extractedBits >> (28 - nLeftShifts))) << (28 * (1 - i)));  // XOR with bit block, shift it left, append overflow bits to right

            }

            return finalBits;

        }

        unsigned long long int sBoxSubs(const unsigned long long int bits) {
            /*
                Performes S-Box substitution on a given set of bits.
            */

            unsigned long long int finalBits, currentBits;
            int row, column;

            const int NUM_BOXES = 8;
            finalBits = 0;

            for (int i = 0; i < NUM_BOXES; i++) {

                currentBits = (((uint64_t)63 << (6 * (NUM_BOXES - 1 - i))) & bits) >> (6 * (NUM_BOXES - 1 - i));     // extract current bits using &
                row = ((32 & currentBits) >> 4) | (1 & currentBits);    // take first and last bits and put them next to each other to form 2 bit row index
                column = (30 & currentBits) >> 1;   // use remaining middle 4 bits for column index

                finalBits = finalBits | ((uint64_t)this->sBoxes[i][row][column] << (4 * (NUM_BOXES - 1 - i)));  // place bits from S-box to designated place

            }

            return finalBits;

        }

        // transformation functions

        unsigned long long int initialPermutation(const unsigned long long int message) { return this->permutate(message, this->IPMatrix, 64, 64); }

        unsigned long long int finalPermutation(const unsigned long long int bits) { return this->permutate(bits, this->IPInverseMatrix, 64, 64); }

        unsigned long long int permutedChoice1(const unsigned long long int key) { return this->permutate(key, this->PC1Matrix, 64, 56); }

        unsigned long long int permutedChoice2(const unsigned long long int bits) { return this->permutate(bits, this->PC2Matrix, 56, 48); }

        unsigned long long int expansionE(const unsigned long long int right) { return this->permutate(right, this->expansionMatrix, 32, 48); }

        unsigned long long int permutationP(const unsigned long long int bits) { return this->permutate(bits, this->permutationMatrix, 32, 32); }

        unsigned long long int fFunction(const unsigned long long int key, const unsigned long long int right) { return this->permutationP(this->sBoxSubs(this->expansionE(right) ^ key)); }

};

#endif