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

namespace Keeg.Crypto.Hashing.Crc
{
    /// <summary>
    /// CRC-64 with reversed data and unreversed output
    /// </summary>
    public sealed class Crc64 : HashAlgorithm
    {
        public const ulong DefaultPolynomial = 0xD800000000000000ul; //Iso 3309 Polynomial
        public const ulong DefaultSeed = 0x0ul;

        private static ulong[] defaultTable;
        private ulong[] table;

        private ulong hash;
        private ulong polynomial;
        private ulong seed;

        public ulong Polynomial
        {
            get => polynomial;
            set
            {
                polynomial = value;
                table = InitializeTable(polynomial);
            }
        }

        public ulong Seed
        {
            get => seed;
            set
            {
                seed = value;
                Initialize();
            }
        }

        public Crc64()
        {
            HashSizeValue = 64;
            seed = DefaultSeed;
            table = InitializeTable(DefaultPolynomial);
            Initialize();
        }

        public override void Initialize()
        {
            hash = seed;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                hash = unchecked((hash >> 8) ^ table[array[i] ^ (hash & 0xFF)]);
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }

        private ulong[] InitializeTable(ulong polynomial)
        {
            if ((polynomial == DefaultPolynomial) && (defaultTable != null))
                return defaultTable;

            var createTable = new ulong[256];
            for (ulong i = 0; i < 256; i++)
            {
                ulong entry = i;
                for (ulong j = 0; j < 8; ++j)
                {
                    if ((entry & 1) == 1)
                    {
                        entry = (entry >> 1) ^ polynomial;
                    }
                    else
                    {
                        entry >>= 1;
                    }
                }
                createTable[i] = entry;
            }

            if (polynomial == DefaultPolynomial)
                defaultTable = createTable;

            return createTable;
        }
    }
}
