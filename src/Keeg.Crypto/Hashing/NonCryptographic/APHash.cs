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

namespace Keeg.Crypto.Hashing.NonCryptographic
{
    /// <summary>
    /// Hashing algorithm by Arash Partow
    /// </summary>
    public sealed class APHash : HashAlgorithm
    {
        #region Instance Fields
        private const uint seed = 0xAAAAAAAAu;
        private uint hash;
        #endregion

        public APHash()
        {
            HashSizeValue = 32;
        }

        new static public APHash Create()
        {
            return Create(typeof(APHash).Name);
        }

        new static public APHash Create(string hashName)
        {
            return (APHash)HashAlgorithmFactory.Create(hashName);
        }

        public override void Initialize()
        {
            hash = seed;
            if ((HashValue != null) && (HashValue.Length > 0))
            {
                Array.Clear(HashValue, 0, HashValue.Length);
                HashValue = null;
            }
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                hash ^= ((i & 0x01) == 0) ? ((hash << 7) ^ array[i] ^ (hash >> 3)) :
                                            (~((hash << 11) ^ array[i] ^ (hash >> 5)));
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
