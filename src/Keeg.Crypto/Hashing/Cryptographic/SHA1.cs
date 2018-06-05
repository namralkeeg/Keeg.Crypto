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
    public sealed class SHA1 : HashAlgorithm
    {
        // split into 64 byte blocks (=> 512 bits)
        private const uint BlockSize = 64; // 512 / 8
        // hash is 20 bytes long
        private const uint HashBytes = 20;
        // hash is 160 bits long
        private const BitSize NumBits = BitSize.Bits160;
        private const uint NumHashValues = 5; // 20 / 4

        private uint m_numBytes;
        private uint m_bufferSize;
        private readonly byte[] m_buffer = new byte[BlockSize];
        private readonly uint[] m_hash = new uint[NumHashValues];

        public SHA1()
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
            m_hash[0] = 0x67452301u;
            m_hash[1] = 0xefcdab89u;
            m_hash[2] = 0x98badcfeu;
            m_hash[3] = 0x10325476u;
            m_hash[4] = 0xc3d2e1f0u;
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

            var words = new uint[80];
            int current = startIndex;
            // convert to big endian
            for (int i = 0; i < 16; i++, current += 4)
            {
                words[i] = BitConverterEndian.ToUInt32BE(block, current);
            }

            // extend to 80 words
            for (int i = 16; i < 80; i++)
            {
                words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).Rol(1);
            }

            // first round
            for (int i = 0; i < 4; i++)
            {
                int offset = 5 * i;
                e += a.Rol(5) + F1(b, c, d) + words[offset    ] + 0x5a827999; b = b.Rol(30);
                d += e.Rol(5) + F1(a, b, c) + words[offset + 1] + 0x5a827999; a = a.Rol(30);
                c += d.Rol(5) + F1(e, a, b) + words[offset + 2] + 0x5a827999; e = e.Rol(30);
                b += c.Rol(5) + F1(d, e, a) + words[offset + 3] + 0x5a827999; d = d.Rol(30);
                a += b.Rol(5) + F1(c, d, e) + words[offset + 4] + 0x5a827999; c = c.Rol(30);
            }

            // second round
            for (int i = 4; i < 8; i++)
            {
                int offset = 5 * i;
                e += a.Rol(5) + F2(b, c, d) + words[offset    ] + 0x6ed9eba1; b = b.Rol(30);
                d += e.Rol(5) + F2(a, b, c) + words[offset + 1] + 0x6ed9eba1; a = a.Rol(30);
                c += d.Rol(5) + F2(e, a, b) + words[offset + 2] + 0x6ed9eba1; e = e.Rol(30);
                b += c.Rol(5) + F2(d, e, a) + words[offset + 3] + 0x6ed9eba1; d = d.Rol(30);
                a += b.Rol(5) + F2(c, d, e) + words[offset + 4] + 0x6ed9eba1; c = c.Rol(30);
            }

            // third round
            for (int i = 8; i < 12; i++)
            {
                int offset = 5 * i;
                e += a.Rol(5) + F3(b, c, d) + words[offset    ] + 0x8f1bbcdc; b = b.Rol(30);
                d += e.Rol(5) + F3(a, b, c) + words[offset + 1] + 0x8f1bbcdc; a = a.Rol(30);
                c += d.Rol(5) + F3(e, a, b) + words[offset + 2] + 0x8f1bbcdc; e = e.Rol(30);
                b += c.Rol(5) + F3(d, e, a) + words[offset + 3] + 0x8f1bbcdc; d = d.Rol(30);
                a += b.Rol(5) + F3(c, d, e) + words[offset + 4] + 0x8f1bbcdc; c = c.Rol(30);
            }

            // fourth round
            for (int i = 12; i < 16; i++)
            {
                int offset = 5 * i;
                e += a.Rol(5) + F2(b, c, d) + words[offset    ] + 0xca62c1d6; b = b.Rol(30);
                d += e.Rol(5) + F2(a, b, c) + words[offset + 1] + 0xca62c1d6; a = a.Rol(30);
                c += d.Rol(5) + F2(e, a, b) + words[offset + 2] + 0xca62c1d6; e = e.Rol(30);
                b += c.Rol(5) + F2(d, e, a) + words[offset + 3] + 0xca62c1d6; d = d.Rol(30);
                a += b.Rol(5) + F2(c, d, e) + words[offset + 4] + 0xca62c1d6; c = c.Rol(30);
            }

            // update hash
            m_hash[0] += a;
            m_hash[1] += b;
            m_hash[2] += c;
            m_hash[3] += d;
            m_hash[4] += e;
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
                m_buffer[addLength++] = (byte)((msgBits >>  8) & 0xFF);
                m_buffer[addLength++] = (byte)(msgBits         & 0xFF);
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
                extra[addLength++] = (byte)((msgBits >>  8) & 0xFF);
                extra[addLength++] = (byte)(msgBits         & 0xFF);
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
            return unchecked(b ^ c ^ d);
        }

        private static uint F3(uint b, uint c, uint d)
        {
            return unchecked((b & c) | (b & d) | (c & d));
        }
    }
}
