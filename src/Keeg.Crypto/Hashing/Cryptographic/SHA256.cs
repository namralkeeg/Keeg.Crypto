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
    public sealed class SHA256 : HashAlgorithm
    {
        // split into 64 byte blocks (=> 512 bits)
        private const uint BlockSize = 64; // 512 / 8
        // hash is 20 bytes long
        private const uint HashBytes = 32;
        // hash is 160 bits long
        private const BitSize NumBits = BitSize.Bits256;
        private const uint NumHashValues = 8; // 20 / 4

        private uint m_numBytes;
        private uint m_bufferSize;
        private readonly byte[] m_buffer = new byte[BlockSize];
        private readonly uint[] m_hash = new uint[NumHashValues];

        public SHA256()
        {
            HashSizeValue = (int)NumBits;
            Initialize();
        }

        public override void Initialize()
        {
            m_numBytes = 0;
            m_bufferSize = 0;
            Array.Clear(m_buffer, 0, m_buffer.Length);
            Array.Clear(m_hash, 0, m_hash.Length);

            // according to RFC 1321
            m_hash[0] = 0x6a09e667;
            m_hash[1] = 0xbb67ae85;
            m_hash[2] = 0x3c6ef372;
            m_hash[3] = 0xa54ff53a;
            m_hash[4] = 0x510e527f;
            m_hash[5] = 0x9b05688c;
            m_hash[6] = 0x1f83d9ab;
            m_hash[7] = 0x5be0cd19;

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
                BitConverterEndian.SetBytesBE(m_hash[i], hash, i * sizeof(uint));
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
            uint e = m_hash[4];
            uint f = m_hash[5];
            uint g = m_hash[6];
            uint h = m_hash[7];

            // data represented as 16x 32-bit words
            var words = new uint[64];
            int current = startIndex;
            // convert to big endian
            for (int j = 0; j < 16; j++, current += 4)
            {
                words[j] = BitConverterEndian.ToUInt32BE(block, current);
            }

            uint x, y; // temporaries

            // first round
            x = h + F1(e, f, g) + 0x428a2f98 + words[0]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0x71374491 + words[1]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0xb5c0fbcf + words[2]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0xe9b5dba5 + words[3]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x3956c25b + words[4]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0x59f111f1 + words[5]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x923f82a4 + words[6]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0xab1c5ed5 + words[7]; y = F2(b, c, d); e += x; a = x + y;

            // secound round
            x = h + F1(e, f, g) + 0xd807aa98 + words[ 8]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0x12835b01 + words[ 9]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0x243185be + words[10]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0x550c7dc3 + words[11]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x72be5d74 + words[12]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0x80deb1fe + words[13]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x9bdc06a7 + words[14]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0xc19bf174 + words[15]; y = F2(b, c, d); e += x; a = x + y;

            int i = 16;
            // extend to 24 words
            for (; i < 24; i++)
            {
                words[i] = words[i - 16] +
                        (words[i - 15].Ror(7) ^ words[i - 15].Ror(18) ^ (words[i - 15] >> 3)) +
                         words[i -  7] +
                        (words[i -  2].Ror(17) ^ words[i - 2].Ror(19) ^ (words[i - 2] >> 10));
            }

            // third round
            x = h + F1(e, f, g) + 0xe49b69c1 + words[16]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0xefbe4786 + words[17]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0x0fc19dc6 + words[18]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0x240ca1cc + words[19]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x2de92c6f + words[20]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0x4a7484aa + words[21]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x5cb0a9dc + words[22]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0x76f988da + words[23]; y = F2(b, c, d); e += x; a = x + y;

            // extend to 32 words
            for (; i < 32; i++)
            {
                words[i] = words[i - 16] +
                        (words[i - 15].Ror(7) ^ words[i - 15].Ror(18) ^ (words[i - 15] >> 3)) +
                         words[i - 7] +
                        (words[i - 2].Ror(17) ^ words[i - 2].Ror(19) ^ (words[i - 2] >> 10));
            }

            // fourth round
            x = h + F1(e, f, g) + 0x983e5152 + words[24]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0xa831c66d + words[25]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0xb00327c8 + words[26]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0xbf597fc7 + words[27]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0xc6e00bf3 + words[28]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0xd5a79147 + words[29]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x06ca6351 + words[30]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0x14292967 + words[31]; y = F2(b, c, d); e += x; a = x + y;

            // extend to 40 words
            for (; i < 40; i++)
            {
                words[i] = words[i - 16] +
                        (words[i - 15].Ror(7) ^ words[i - 15].Ror(18) ^ (words[i - 15] >> 3)) +
                         words[i - 7] +
                        (words[i - 2].Ror(17) ^ words[i - 2].Ror(19) ^ (words[i - 2] >> 10));
            }

            // fifth round
            x = h + F1(e, f, g) + 0x27b70a85 + words[32]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0x2e1b2138 + words[33]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0x4d2c6dfc + words[34]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0x53380d13 + words[35]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x650a7354 + words[36]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0x766a0abb + words[37]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x81c2c92e + words[38]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0x92722c85 + words[39]; y = F2(b, c, d); e += x; a = x + y;

            // extend to 48 words
            for (; i < 48; i++)
            {
                words[i] = words[i - 16] +
                        (words[i - 15].Ror(7) ^ words[i - 15].Ror(18) ^ (words[i - 15] >> 3)) +
                         words[i - 7] +
                        (words[i - 2].Ror(17) ^ words[i - 2].Ror(19) ^ (words[i - 2] >> 10));
            }

            // sixth round
            x = h + F1(e, f, g) + 0xa2bfe8a1 + words[40]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0xa81a664b + words[41]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0xc24b8b70 + words[42]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0xc76c51a3 + words[43]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0xd192e819 + words[44]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0xd6990624 + words[45]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0xf40e3585 + words[46]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0x106aa070 + words[47]; y = F2(b, c, d); e += x; a = x + y;

            // extend to 56 words
            for (; i < 56; i++)
            {
                words[i] = words[i - 16] +
                        (words[i - 15].Ror(7) ^ words[i - 15].Ror(18) ^ (words[i - 15] >> 3)) +
                         words[i - 7] +
                        (words[i - 2].Ror(17) ^ words[i - 2].Ror(19) ^ (words[i - 2] >> 10));
            }

            // seventh round
            x = h + F1(e, f, g) + 0x19a4c116 + words[48]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0x1e376c08 + words[49]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0x2748774c + words[50]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0x34b0bcb5 + words[51]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x391c0cb3 + words[52]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0x4ed8aa4a + words[53]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x5b9cca4f + words[54]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0x682e6ff3 + words[55]; y = F2(b, c, d); e += x; a = x + y;

            // extend to 64 words
            for (; i < 64; i++)
            {
                words[i] = words[i - 16] +
                        (words[i - 15].Ror(7) ^ words[i - 15].Ror(18) ^ (words[i - 15] >> 3)) +
                         words[i - 7] +
                        (words[i - 2].Ror(17) ^ words[i - 2].Ror(19) ^ (words[i - 2] >> 10));
            }

            // eigth round
            x = h + F1(e, f, g) + 0x748f82ee + words[56]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0x78a5636f + words[57]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0x84c87814 + words[58]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0x8cc70208 + words[59]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x90befffa + words[60]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0xa4506ceb + words[61]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0xbef9a3f7 + words[62]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0xc67178f2 + words[63]; y = F2(b, c, d); e += x; a = x + y;

            // update hash
            m_hash[0] += a;
            m_hash[1] += b;
            m_hash[2] += c;
            m_hash[3] += d;
            m_hash[4] += e;
            m_hash[5] += f;
            m_hash[6] += g;
            m_hash[7] += h;
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

                // must be big endian
                m_buffer[addLength++] = (byte)((msgBits >> 56) & 0xFF);
                m_buffer[addLength++] = (byte)((msgBits >> 48) & 0xFF);
                m_buffer[addLength++] = (byte)((msgBits >> 40) & 0xFF);
                m_buffer[addLength++] = (byte)((msgBits >> 32) & 0xFF);
                m_buffer[addLength++] = (byte)((msgBits >> 24) & 0xFF);
                m_buffer[addLength++] = (byte)((msgBits >> 16) & 0xFF);
                m_buffer[addLength++] = (byte)((msgBits >> 8) & 0xFF);
                m_buffer[addLength++] = (byte)(msgBits & 0xFF);
            }
            else
            {
                addLength = paddedLength - BlockSize;

                // must be big endian
                extra[addLength++] = (byte)((msgBits >> 56) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 48) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 40) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 32) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 24) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 16) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 8) & 0xFF);
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

        private static uint F1(uint e, uint f, uint g)
        {
            uint term1 = unchecked(e.Ror(6) ^ e.Ror(11) ^ e.Ror(25));
            uint term2 = unchecked((e & f) ^ (~e & g)); //(g ^ (e & (f ^ g)))
            return term1 + term2;
        }

        private static uint F2(uint a, uint b, uint c)
        {
            uint term1 = unchecked(a.Ror(2) ^ a.Ror(13) ^ a.Ror(22));
            uint term2 = unchecked(((a | b) & c) | (a & b)); //(a & (b ^ c)) ^ (b & c);
            return term1 + term2;
        }
    }
}
