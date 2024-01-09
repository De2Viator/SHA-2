#include <utility>
#include <vector>
#include <cstdint>
#include <string>
#include <bitset>
#include <sstream>
#include <iostream>
#include "sha2.h"

size h[H_SIZE] = INITIAL_H;
size k[K_SIZE] = K;
std::string parseMessageToBinary(std::string message) {
    std::ostringstream parsedMessageStream;
    for (char& c : message) {
        int asciiValue = static_cast<int>(c);
        std::string binaryString = std::bitset<8>(asciiValue).to_string();
        parsedMessageStream<<binaryString;
    }
    std::string parsedMessage = parsedMessageStream.str();
    return parsedMessage;
}
void padMessage(std::string & message) {
    message+='1';
    while (message.length() % SHA_SIZE != SHA_SIZE_WITHOUT_MESSAGE_SIZE) {
        message.push_back('0');
    }
}
std::string fromBnToHex(std::string binaryMessage) {
    std::ostringstream hexStream;

    for (size_t i = 0; i < binaryMessage.length(); i += 4) {
        std::string fourBits = binaryMessage.substr(i, 4);
        std::bitset<4> bitset(fourBits);
        int hexValue = bitset.to_ulong();
        hexStream << std::hex << hexValue;
    }
    return hexStream.str();
}
std::string hexSize(unsigned long long number) {
    std::ostringstream hexedSize;
    hexedSize << std::hex << number;
    std::string hexedNumber = hexedSize.str();
    if(hexedNumber.length() < BITS_SIZE) hexedNumber = std::string(BITS_SIZE-hexedNumber.length(),'0') + hexedNumber;
    return hexedNumber;
}
size ROTR(size value, unsigned int shift) {
    return (value >> shift) | (value << (MESSAGE_BITS - shift));
}
size SHR(size value, unsigned int shift) {
    return value >> shift;
}
std::vector<std::string> divideByBlocks(std::string message) {
    std::vector<std::string> blocks;
    for(unsigned long long i =0; i < message.length();i+=SHA_BLOCK_SIZE) {
        std::string block = message.substr(i,SHA_BLOCK_SIZE);
        blocks.push_back(block);
    }
    return blocks;
}
std::vector<size> divideStringByWords(std::string message) {
    std::vector<size> words;
    for (int i = 0; i < message.size(); i += 8) {
        std::string wordStr = message.substr(i, 8);
        size word;
        std::istringstream(wordStr) >> std::hex >> word;
        words.push_back(word);
    }
    return words;
}
void encryptBlock(std::string & block) {
    std::vector<size> words =  divideStringByWords(block);
    for(int i = START_WORDS_AMOUNT; i < FINAL_WORDS_AMOUNT;i++) {
        size s0 = ROTR(words[i-15],7) ^ ROTR(words[i-15],18) ^SHR(words[i-15], 3);
        size s1 = ROTR(words[i-2],17) ^ ROTR(words[i-2],19) ^ SHR(words[i-2],10);
        size result = words[i-16] + s0 + words[i-7] + s1;
        words.push_back(result);
    }
    size A = h[0];
    size B = h[1];
    size C = h[2];
    size D = h[3];
    size E = h[4];
    size F = h[5];
    size G = h[6];
    size H = h[7];
    for (unsigned short i =0; i < FINAL_WORDS_AMOUNT;i++) {
        size sigma0 = ROTR(A,2) ^ ROTR(A,13) ^ ROTR(A,22);
        size Ma = (A & B) ^ (A & C) ^ (B & C);
        size t2 = sigma0+Ma;
        size sigma1 = ROTR(E,6) ^ ROTR(E,11) ^ ROTR(E,25);
        size Ch = (E & F) ^ ((~E) & G);
        size t1 = H + Ch + sigma1 + k[i] + words[i];

        H=G;
        G=F;
        F=E;
        E=D+t1;
        D=C;
        C=B;
        B=A;
        A=t1+t2;
    }
    h[0]+=A;
    h[1]+=B;
    h[2]+=C;
    h[3]+=D;
    h[4]+=E;
    h[5]+=F;
    h[6]+=G;
    h[7]+=H;
}
std::string makeHash() {
    std::ostringstream hashStream;
    for (unsigned short i = 0; i < H_SIZE; i++) {
        std::ostringstream hexStream;
        hexStream << std::hex << h[i];
        std::string hexH = hexStream.str();
        if(hexH.length() < 8) {
            hexH = std::string(BITSET_SIZE - hexH.length(),'0' ) + hexH;
        }
        hashStream<<hexH;
    }
    return hashStream.str();
}
std::string SHA_2(std::string initialMessage) {
    std::string message = parseMessageToBinary(initialMessage);
    unsigned long long size = message.size();

    padMessage(message);
    std::string hexedMessage = fromBnToHex(message);
    hexedMessage += hexSize(size);
    std::vector<std::string> blocks = divideByBlocks(hexedMessage);
    for (auto & block : blocks) {
        encryptBlock(block);
    }
    std::string hash = makeHash();
    return hash;
}
int main() {
    std::string message = "TESTAAASSSASADAABBBBBBBBJJJJJJJJJKKKKKKKKKNNNNNNNNNNWZM";
    std::string hash = SHA_2(message);
    std::cout<<"SHA-2 hash:"<<hash;
    return 0;
}
