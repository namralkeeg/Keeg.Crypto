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
    public sealed class SHA3 : HashAlgorithm
    {
        #region Constants
        /// 1600 bits, stored as 25x64 bit, BlockSize is no more than 1152 bits (Keccak224)
        private const uint StateSize = 25;      // 1600 / (8 * 8)
        private const uint MaxBlockSize = 144;  // 200 - 2 * (224 / 8)
        private const uint Rounds = 24;
        private const BitSize DefaultBitsize = BitSize.Bits256;
        #endregion

        #region Fields
        private static readonly ulong[] XorMasks = new ulong[]
        {
            0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aul,
            0x8000000080008000UL, 0x000000000000808bUL, 0x0000000080000001UL,
            0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008aUL,
            0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
            0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL,
            0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
            0x000000000000800aUL, 0x800000008000000aUL, 0x8000000080008081UL,
            0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
        };

        /// hash
        private ulong[] hash = new ulong[StateSize];
        /// bytes not processed yet
        private byte[] buffer = new byte[MaxBlockSize];
        /// block size (less or equal to MaxBlockSize)
        private uint blockSize;
        /// valid bytes in m_buffer
        private uint bufferSize;
        /// size of processed data in bytes
        private uint numBytes;
        private BitSize bits;
        #endregion

        #region Properties
        public BitSize Bits
        {
            get => bits;
            set
            {
                switch (value)
                {
                    case BitSize.Bits224:
                    case BitSize.Bits256:
                    case BitSize.Bits384:
                    case BitSize.Bits512:
                        bits = value;
                        blockSize = 200 - 2 * (uint)((int)bits / 8);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(value));
                }
            }
        }

        public override int HashSize => (int)bits;
        public override int OutputBlockSize => (int)blockSize;
        #endregion

        public SHA3() : this(DefaultBitsize)
        { }

        public SHA3(BitSize bitSize)
        {
            Bits = bitSize;
            Initialize();
        }

        public static new SHA3 Create()
        {
            return Create(typeof(SHA3).Name);
        }

        public static new SHA3 Create(string hashName)
        {
            return (SHA3)HashAlgorithmFactory.Create(hashName);
        }

        public override void Initialize()
        {
            numBytes = 0;
            bufferSize = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            uint bytesLeft = (uint)cbSize;
            uint current = (uint)ibStart;

            // Copy data to buffer
            if (bufferSize > 0)
            {
                while ((bytesLeft > 0) && (bufferSize < blockSize))
                {
                    buffer[bufferSize++] = array[current++];
                    bytesLeft--;
                }
            }

            // full buffer
            if (bufferSize == blockSize)
            {
                ProcessBlock(buffer, 0);
                numBytes += blockSize;
                bufferSize = 0;
            }

            // more data ?
            if (bytesLeft > 0)
            {
                // process full blocks
                while (bytesLeft >= blockSize)
                {
                    ProcessBlock(array, (int)current);
                    current += blockSize;
                    numBytes += blockSize;
                    bytesLeft -= blockSize;
                }

                // keep remaining bytes in buffer
                while (bytesLeft > 0)
                {
                    buffer[bufferSize++] = array[current++];
                    bytesLeft--;
                }
            }
        }

        protected override byte[] HashFinal()
        {
            // process remaining bytes
            ProcessBuffer();

            // number of significant elements in hash
            int hashLength = (int)bits / 64;
            var hashTemp = new byte[(int)bits / 8];
            int current = 0;
            for (uint i = 0; i < hashLength; i++, current += 8)
            {
                BitConverterEndian.SetBytesLE(hash[i], hashTemp, current);
            }

            // SHA3-224's last entry in hash provides only 32 bits instead of 64 bits
            int remainder = (int)bits - hashLength * 64;
            int processed = 0;
            while (processed < remainder)
            {
                hashTemp[current++] = (byte)((hash[hashLength] >> processed) & 0xFF);
                processed += 8;
            }

            return hashTemp;
        }

        /// return x % 5 for 0 <= x <= 9
        private static uint Mod5(uint x)
        {
            if (x < 5)
            {
                return x;
            }

            return x - 5;
        }

        private void ProcessBlock(byte[] block, int startIndex)
        {
            for (var i = 0; i < blockSize / 8; i++)
            {
                unchecked
                {
                    hash[i] ^= BitConverterEndian.ToUInt64LE(block, startIndex + (8 * i));
                }
            }

            // re-compute state
            for (uint round = 0; round < Rounds; round++)
            {
                // Theta
                var coefficients = new ulong[5];
                for (var i = 0; i < 5; i++)
                {
                    coefficients[i] = unchecked(hash[i] ^ hash[i + 5] ^ hash[i + 10] ^ hash[i + 15] ^ hash[i + 20]);
                }

                ulong one;
                for (uint i = 0; i < 5; i++)
                {
                    unchecked
                    {
                        one = coefficients[Mod5(i + 4)] ^ coefficients[Mod5(i + 1)].Rol(1);
                        hash[i] ^= one;
                        hash[i + 5] ^= one;
                        hash[i + 10] ^= one;
                        hash[i + 15] ^= one;
                        hash[i + 20] ^= one;
                    }
                }

                // Rho Pi
                ulong last = hash[1];
                one = hash[10]; hash[10] = last.Rol(1);  last = one;
                one = hash[7];  hash[7]  = last.Rol(3);  last = one;
                one = hash[11]; hash[11] = last.Rol(6);  last = one;
                one = hash[17]; hash[17] = last.Rol(10); last = one;
                one = hash[18]; hash[18] = last.Rol(15); last = one;
                one = hash[3];  hash[3]  = last.Rol(21); last = one;
                one = hash[5];  hash[5]  = last.Rol(28); last = one;
                one = hash[16]; hash[16] = last.Rol(36); last = one;
                one = hash[8];  hash[8]  = last.Rol(45); last = one;
                one = hash[21]; hash[21] = last.Rol(55); last = one;
                one = hash[24]; hash[24] = last.Rol(2);  last = one;
                one = hash[4];  hash[4]  = last.Rol(14); last = one;
                one = hash[15]; hash[15] = last.Rol(27); last = one;
                one = hash[23]; hash[23] = last.Rol(41); last = one;
                one = hash[19]; hash[19] = last.Rol(56); last = one;
                one = hash[13]; hash[13] = last.Rol(8);  last = one;
                one = hash[12]; hash[12] = last.Rol(25); last = one;
                one = hash[2];  hash[2]  = last.Rol(43); last = one;
                one = hash[20]; hash[20] = last.Rol(62); last = one;
                one = hash[14]; hash[14] = last.Rol(18); last = one;
                one = hash[22]; hash[22] = last.Rol(39); last = one;
                one = hash[9];  hash[9]  = last.Rol(61); last = one;
                one = hash[6];  hash[6]  = last.Rol(20); last = one;
                                hash[1]  = last.Rol(44);

                ulong two;
                // Chi
                for (uint j = 0; j < 25; j += 5)
                {
                    // temporaries
                    one = hash[j];
                    two = hash[j + 1];
                    
                    unchecked
                    {
                        hash[j] ^= hash[j + 2] & ~two;
                        hash[j + 1] ^= hash[j + 3] & ~hash[j + 2];
                        hash[j + 2] ^= hash[j + 4] & ~hash[j + 3];
                        hash[j + 3] ^= one & ~hash[j + 4];
                        hash[j + 4] ^= two & ~one;
                    }
                }

                // Iota
                hash[0] ^= XorMasks[round];
            }
        }

        private void ProcessBuffer()
        {
            // add padding
            uint offset = bufferSize;
            
            // add a "1" byte
            buffer[offset++] = 0x06;

            // fill with zeros
            while (offset < blockSize)
            {
                buffer[offset++] = 0;
            }

            // and add a single set bit
            buffer[offset - 1] |= 0x80;

            ProcessBlock(buffer, 0);
        }
    }
}
