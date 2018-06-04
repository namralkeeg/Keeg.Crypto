#region Copyright
/*
 * Copyright (C) 2018 Larry Lopez
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#endregion
using System;
using System.Security.Cryptography;
using Keeg.Crypto.Common;

namespace Keeg.Crypto.Hashing.Cryptographic
{
    public sealed class MD5 : HashAlgorithm
    {
        /// split into 64 byte blocks (=> 512 bits)
        private const uint BlockSize = 64;       // 512 / 8
        private const uint HashBytes = 16;
        private const uint NumHashValues = 4;    // 16 / 4
        private const BitSize NumBits = BitSize.Bits128;

        private uint m_numBytes;
        private uint m_bufferSize;
        private byte[] m_buffer = new byte[BlockSize];
        private uint[] m_hash = new uint[NumHashValues];

        public MD5()
        {
            HashSizeValue = (int)NumBits;
            Initialize();
        }

        public static new MD5 Create()
        {
            return Create(typeof(MD5).Name);
        }

        public static new MD5 Create(string hashName)
        {
            return (MD5)HashAlgorithmFactory.Create(hashName);
        }

        public override void Initialize()
        {
            m_numBytes = 0;
            m_bufferSize = 0;
            Array.Clear(m_buffer, 0, m_buffer.Length);
            Array.Clear(m_hash, 0, m_hash.Length);

            // according to RFC 1321
            m_hash[0] = 0x67452301u;
            m_hash[1] = 0xefcdab89u;
            m_hash[2] = 0x98badcfeu;
            m_hash[3] = 0x10325476u;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int numBytes = cbSize;
            int current = ibStart;

            if (m_bufferSize > 0)
            {
                while ((numBytes > 0) && (m_bufferSize < BlockSize))
                {
                    m_buffer[m_bufferSize++] = array[current++];
                    numBytes--;
                }
            }

            // Full buffer
            if (m_bufferSize == BlockSize)
            {
                ProcessBlock(m_buffer, 0);
                m_numBytes += BlockSize;
                m_bufferSize = 0;
            }

            if (numBytes > 0)
            {
                // process full blocks
                while (numBytes >= BlockSize)
                {
                    ProcessBlock(array, current);
                    current += (int)BlockSize;
                    m_numBytes += BlockSize;
                    numBytes -= (int)BlockSize;
                }

                // keep remaining bytes in buffer
                while (numBytes > 0)
                {
                    m_buffer[m_bufferSize++] = array[current++];
                    numBytes--;
                }
            }
        }

        protected override byte[] HashFinal()
        {
            // save old hash if buffer is partially filled
            var oldHash = new uint[NumHashValues];
            Array.Copy(m_hash, oldHash, m_hash.Length);

            // process remaining bytes
            ProcessBuffer();

            var hash = new byte[HashBytes];
            for (int i = 0; i < NumHashValues; i++)
            {
                BitConverterEndian.SetBytesLE(m_hash[i], hash, i * sizeof(uint));
            }

            // Restore the old hash.
            Array.Copy(oldHash, m_hash, oldHash.Length);

            return hash;
        }

        private void ProcessBlock(byte[] block, int startIndex)
        {
            // get last hash
            uint a = m_hash[0];
            uint b = m_hash[1];
            uint c = m_hash[2];
            uint d = m_hash[3];

            // first round
            uint word0 = BitConverterEndian.ToUInt32LE(block, 0 * sizeof(uint));
            a = (a + F1(b, c, d) + word0 + 0xd76aa478).Rol(7) + b;
            uint word1 = BitConverterEndian.ToUInt32LE(block, 1 * sizeof(uint));
            d = (d + F1(a, b, c) + word1 + 0xe8c7b756).Rol(12) + a;
            uint word2 = BitConverterEndian.ToUInt32LE(block, 2 * sizeof(uint));
            c = (c + F1(d, a, b) + word2 + 0x242070db).Rol(17) + d;
            uint word3 = BitConverterEndian.ToUInt32LE(block, 3 * sizeof(uint));
            b = (b + F1(c, d, a) + word3 + 0xc1bdceee).Rol(22) + c;

            uint word4 = BitConverterEndian.ToUInt32LE(block, 4 * sizeof(uint));
            a = (a + F1(b, c, d) + word4 + 0xf57c0faf).Rol(7) + b;
            uint word5 = BitConverterEndian.ToUInt32LE(block, 5 * sizeof(uint));
            d = (d + F1(a, b, c) + word5 + 0x4787c62a).Rol(12) + a;
            uint word6 = BitConverterEndian.ToUInt32LE(block, 6 * sizeof(uint));
            c = (c + F1(d, a, b) + word6 + 0xa8304613).Rol(17) + d;
            uint word7 = BitConverterEndian.ToUInt32LE(block, 7 * sizeof(uint));
            b = (b + F1(c, d, a) + word7 + 0xfd469501).Rol(22) + c;

            uint word8 = BitConverterEndian.ToUInt32LE(block, 8 * sizeof(uint));
            a = (a + F1(b, c, d) + word8 + 0x698098d8).Rol(7) + b;
            uint word9 = BitConverterEndian.ToUInt32LE(block, 9 * sizeof(uint));
            d = (d + F1(a, b, c) + word9 + 0x8b44f7af).Rol(12) + a;
            uint word10 = BitConverterEndian.ToUInt32LE(block, 10 * sizeof(uint));
            c = (c + F1(d, a, b) + word10 + 0xffff5bb1).Rol(17) + d;
            uint word11 = BitConverterEndian.ToUInt32LE(block, 11 * sizeof(uint));
            b = (b + F1(c, d, a) + word11 + 0x895cd7be).Rol(22) + c;

            uint word12 = BitConverterEndian.ToUInt32LE(block, 12 * sizeof(uint));
            a = (a + F1(b, c, d) + word12 + 0x6b901122).Rol(7) + b;
            uint word13 = BitConverterEndian.ToUInt32LE(block, 13 * sizeof(uint));
            d = (d + F1(a, b, c) + word13 + 0xfd987193).Rol(12) + a;
            uint word14 = BitConverterEndian.ToUInt32LE(block, 14 * sizeof(uint));
            c = (c + F1(d, a, b) + word14 + 0xa679438e).Rol(17) + d;
            uint word15 = BitConverterEndian.ToUInt32LE(block, 15 * sizeof(uint));
            b = (b + F1(c, d, a) + word15 + 0x49b40821).Rol(22) + c;

            // second round
            a = (a + F2(b, c, d) + word1 + 0xf61e2562).Rol(5) + b;
            d = (d + F2(a, b, c) + word6 + 0xc040b340).Rol(9) + a;
            c = (c + F2(d, a, b) + word11 + 0x265e5a51).Rol(14) + d;
            b = (b + F2(c, d, a) + word0 + 0xe9b6c7aa).Rol(20) + c;

            a = (a + F2(b, c, d) + word5 + 0xd62f105d).Rol(5) + b;
            d = (d + F2(a, b, c) + word10 + 0x02441453).Rol(9) + a;
            c = (c + F2(d, a, b) + word15 + 0xd8a1e681).Rol(14) + d;
            b = (b + F2(c, d, a) + word4 + 0xe7d3fbc8).Rol(20) + c;

            a = (a + F2(b, c, d) + word9 + 0x21e1cde6).Rol(5) + b;
            d = (d + F2(a, b, c) + word14 + 0xc33707d6).Rol(9) + a;
            c = (c + F2(d, a, b) + word3 + 0xf4d50d87).Rol(14) + d;
            b = (b + F2(c, d, a) + word8 + 0x455a14ed).Rol(20) + c;

            a = (a + F2(b, c, d) + word13 + 0xa9e3e905).Rol(5) + b;
            d = (d + F2(a, b, c) + word2 + 0xfcefa3f8).Rol(9) + a;
            c = (c + F2(d, a, b) + word7 + 0x676f02d9).Rol(14) + d;
            b = (b + F2(c, d, a) + word12 + 0x8d2a4c8a).Rol(20) + c;

            // third round
            a = (a + F3(b, c, d) + word5 + 0xfffa3942).Rol(4) + b;
            d = (d + F3(a, b, c) + word8 + 0x8771f681).Rol(11) + a;
            c = (c + F3(d, a, b) + word11 + 0x6d9d6122).Rol(16) + d;
            b = (b + F3(c, d, a) + word14 + 0xfde5380c).Rol(23) + c;

            a = (a + F3(b, c, d) + word1 + 0xa4beea44).Rol(4) + b;
            d = (d + F3(a, b, c) + word4 + 0x4bdecfa9).Rol(11) + a;
            c = (c + F3(d, a, b) + word7 + 0xf6bb4b60).Rol(16) + d;
            b = (b + F3(c, d, a) + word10 + 0xbebfbc70).Rol(23) + c;

            a = (a + F3(b, c, d) + word13 + 0x289b7ec6).Rol(4) + b;
            d = (d + F3(a, b, c) + word0 + 0xeaa127fa).Rol(11) + a;
            c = (c + F3(d, a, b) + word3 + 0xd4ef3085).Rol(16) + d;
            b = (b + F3(c, d, a) + word6 + 0x04881d05).Rol(23) + c;

            a = (a + F3(b, c, d) + word9 + 0xd9d4d039).Rol(4) + b;
            d = (d + F3(a, b, c) + word12 + 0xe6db99e5).Rol(11) + a;
            c = (c + F3(d, a, b) + word15 + 0x1fa27cf8).Rol(16) + d;
            b = (b + F3(c, d, a) + word2 + 0xc4ac5665).Rol(23) + c;

            // fourth round
            a = (a + F4(b, c, d) + word0 + 0xf4292244).Rol(6) + b;
            d = (d + F4(a, b, c) + word7 + 0x432aff97).Rol(10) + a;
            c = (c + F4(d, a, b) + word14 + 0xab9423a7).Rol(15) + d;
            b = (b + F4(c, d, a) + word5 + 0xfc93a039).Rol(21) + c;

            a = (a + F4(b, c, d) + word12 + 0x655b59c3).Rol(6) + b;
            d = (d + F4(a, b, c) + word3 + 0x8f0ccc92).Rol(10) + a;
            c = (c + F4(d, a, b) + word10 + 0xffeff47d).Rol(15) + d;
            b = (b + F4(c, d, a) + word1 + 0x85845dd1).Rol(21) + c;

            a = (a + F4(b, c, d) + word8 + 0x6fa87e4f).Rol(6) + b;
            d = (d + F4(a, b, c) + word15 + 0xfe2ce6e0).Rol(10) + a;
            c = (c + F4(d, a, b) + word6 + 0xa3014314).Rol(15) + d;
            b = (b + F4(c, d, a) + word13 + 0x4e0811a1).Rol(21) + c;

            a = (a + F4(b, c, d) + word4 + 0xf7537e82).Rol(6) + b;
            d = (d + F4(a, b, c) + word11 + 0xbd3af235).Rol(10) + a;
            c = (c + F4(d, a, b) + word2 + 0x2ad7d2bb).Rol(15) + d;
            b = (b + F4(c, d, a) + word9 + 0xeb86d391).Rol(21) + c;

            // update hash
            m_hash[0] += a;
            m_hash[1] += b;
            m_hash[2] += c;
            m_hash[3] += d;
        }

        private void ProcessBuffer()
        {
            // the input bytes are considered as bits strings, where the first bit is the most significant bit of the byte

            // - append "1" bit to message
            // - append "0" bits until message length in bit mod 512 is 448
            // - append length as 64 bit integer

            // number of bits
            uint paddedLength = m_bufferSize * 8;

            // plus one bit set to 1 (always appended)
            paddedLength++;

            // number of bits must be (numBits % 512) = 448
            uint lower11Bits = paddedLength & 511;
            if (lower11Bits <= 448)
            {
                paddedLength += 448 - lower11Bits;
            }
            else
            {
                paddedLength += 512 + 448 - lower11Bits;
            }
            // convert from bits to bytes
            paddedLength /= 8;

            // only needed if additional data flows over into a second block
            var extra = new byte[BlockSize];

            // append a "1" bit, 128 => binary 10000000
            if (m_bufferSize < BlockSize)
            {
                m_buffer[m_bufferSize] = 128;
            }
            else
            {
                extra[0] = 128;
            }

            uint i;
            for (i = m_bufferSize + 1; i < BlockSize; i++)
            {
                m_buffer[i] = 0;
            }

            for (; i < paddedLength; i++)
            {
                extra[i - BlockSize] = 0;
            }

            // add message length in bits as 64 bit number
            ulong msgBits = 8 * (m_numBytes + m_bufferSize);
            // find right position
            uint addLength;
            if (paddedLength < BlockSize)
            {
                addLength = paddedLength;

                // must be little endian
                m_buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                m_buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                m_buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                m_buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                m_buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                m_buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                m_buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                m_buffer[addLength++] = (byte)(msgBits & 0xFF);
            }
            else
            {
                addLength = paddedLength - BlockSize;

                // must be little endian
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF);
            }

            // process blocks
            ProcessBlock(m_buffer, 0);

            // flowed over into a second block ?
            if (paddedLength > BlockSize)
            {
                ProcessBlock(extra, 0);
            }
        }

        private static uint F1(uint b, uint c, uint d)
        {
            return unchecked(d ^ (b & (c ^ d))); // original: f = (b & c) | ((~b) & d);
        }

        private static uint F2(uint b, uint c, uint d)
        {
            return unchecked(c ^ (d & (b ^ c))); // original: f = (b & d) | (c & (~d));
        }

        private static uint F3(uint b, uint c, uint d)
        {
            return unchecked(b ^ c ^ d);
        }

        private static uint F4(uint b, uint c, uint d)
        {
            return unchecked(c ^ (b | ~d));
        }
    }
}
