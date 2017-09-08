using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MD5Gen
{
    public sealed class MD5
    {
        //Sources from wiki.
        //https://en.wikipedia.org/wiki/MD5
        //Used the precomputed table.
        private readonly static uint[] k = new uint[]
            {
                0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
                0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
                0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
                0x6b901122,0xfd987193,0xa679438e,0x49b40821,
                0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
                0xd62f105d,0x2441453,0xd8a1e681,0xe7d3fbc8,
                0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
                0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
                0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
                0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
                0x289b7ec6,0xeaa127fa,0xd4ef3085,0x4881d05,
                0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
                0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
                0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
                0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
                0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
            };

        private uint A = 0x67452301;
        private uint B = 0xEFCDAB89;
        private uint C = 0x98BADCFE;
        private uint D = 0X10325476;

        private readonly static int[] s = new int[64]
        {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        };

        private readonly uint[] x = new uint[16];
        private readonly byte[] inputBytes;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="givenString">Your given message.</param>
        public MD5(string givenString)
        {
            inputBytes = new byte[givenString.Length];
            for (int i = 0; i < givenString.Length; ++i)
            {
                inputBytes[i] = (byte) (givenString[i]);
            }

        }

        /// <summary>
        /// Generates a MD5 Hash.
        /// </summary>
        /// <returns>The generated Hash</returns>
        public string GenHash()
        {
            byte[] blockMessage = PadBuffer();

            uint n = (uint) ((blockMessage.Length * 8) / 32);

            for (uint i = 0; i < n / 16; ++i)
            {
                MakeBlock(blockMessage, i);
                CalcTransform();
            }

            return ( ReverseByte(A).ToString("X8") + ReverseByte(B).ToString("X8") 
                      + ReverseByte(C).ToString("X8") + ReverseByte(D).ToString("X8"));
        }

        private static uint ReverseByte(uint Num)
        {
            return (((Num & 0x000000ff) << 24) | (Num >> 24) 
                | ((Num & 0x00ff0000) >> 8) | ((Num & 0x0000ff00) << 8));
        }

        private void CalcTransform()
        {
            uint tempA = A, tempB = B, tempC = C, tempD = D, F = 0;
            int g = 0;

            for (int i = 0; i < 64; ++i)
            {
                if (i <= 15)
                {
                    F = ((tempB & tempC) | (~(tempB) & tempD));
                    g = i;
                }
                else if (i <= 31)
                {
                    F = ((tempB & tempD) | (tempC & ~tempD));
                    g = (5 * i + 1) % 16;
                }
                else if (i <= 47)
                {
                    F = (tempB ^ tempC ^ tempD);
                    g = (3 * i + 5) % 16;
                }
                else if (i <= 63)
                {
                    F = (tempC ^ (tempB | ~tempD));
                    g = (7 * i) % 16;
                }
                uint currentDD = tempD;
                tempD = tempC;
                tempC = tempB;
                uint calValue = tempA + F + (k[i] + x[g]);
                calValue = (calValue << s[i]) | (calValue >> (32 - s[i]));
                tempB = tempB + calValue;
                tempA = currentDD;
            }

            A += tempA;
            B += tempB;
            C += tempC;
            D += tempD;
        }

        private void MakeBlock(byte[] blockMessage, uint block)
        {
            block = block << 6;
            for (uint i = 0; i < 61; i += 4)
            {
                x[i >> 2] = (((uint) (blockMessage[block + (i + 3)])) << 24) | (((uint) (blockMessage[block + (i + 2)])) << 16) 
                         | (((uint) (blockMessage[block + (i + 1)])) << 8) | ((blockMessage[block + (i)]));
            }
        }


        private byte[] PadBuffer()
        {
            uint pad = (uint)(((448 - ((inputBytes.Length * 8) % 512)) + 512) % 512);

            if (pad == 0)
            {
                pad = 512;
            }

            uint bufferSize = (uint)((inputBytes.Length) + (pad / 8) + 8);
            ulong messageSize = (ulong) (inputBytes.Length * 8);

            byte[] paddedBuffer = new byte[bufferSize];

            Array.Copy(inputBytes, paddedBuffer, inputBytes.Length);

            paddedBuffer[inputBytes.Length] |= 0x80;

            for (int i = 8; i > 0; --i)
            {
                //0x00000000000000ff == 0xff
                paddedBuffer[bufferSize - i] = (byte) (messageSize >> ((8 - i) * 8) & 0xff);
            }

            return paddedBuffer;
        }
    }
}
