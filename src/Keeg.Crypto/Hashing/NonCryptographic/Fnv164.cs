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
    /// Fowler/Noll/Vo or FNV1 64 bit hash.
    /// See a detailed description at http://www.isthe.com/chongo/tech/comp/fnv/
    /// </summary>
    public class Fnv164 : HashAlgorithm
    {
        protected const ulong fnvPrime = 0x00000100000001B3ul;
        protected const ulong offsetBasis = 0xCBF29CE484222325ul;
        protected ulong hash;

        public Fnv164()
        {
            HashSizeValue = 64;
            Initialize();
        }

        public static new Fnv164 Create()
        {
            return Create(typeof(Fnv164).Name);
        }

        public static new Fnv164 Create(string hashName)
        {
            return (Fnv164)HashAlgorithmFactory.Create(hashName);
        }

        public override void Initialize()
        {
            hash = offsetBasis;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                unchecked
                {
                    hash *= fnvPrime;
                    hash ^= array[i];
                }
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
