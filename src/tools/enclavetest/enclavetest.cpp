// Console17.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

extern "C" {
    void test_verify(const char* filename, const char* sectionname);
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        printf("Usage: enclavetest <filename> <sectionname>\n");
        printf("       If a path is present in the filename, use / not \\ to separate segments.\n");
        printf("       If a full path is used, a drive letter is not permitted.\n");
        printf("       If a relative path is used, it is relative to the root directory of the current drive.\n");
        return 1;
    }
    const char* filename = argv[1];
    const char* sectionname = argv[2];

    test_verify(filename, sectionname);
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
