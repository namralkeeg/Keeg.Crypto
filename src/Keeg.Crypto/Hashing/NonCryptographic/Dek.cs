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
    /// An algorithm proposed by Donald E. Knuth in The Art Of Computer Programming Volume 3.
    /// </summary>
    public sealed class Dek : HashAlgorithm
    {
        private uint hash;
        private const uint seed = 0;

        public Dek()
        {
            HashSizeValue = 32;
            Initialize();
        }

        new static public Dek Create()
        {
            return Create(typeof(Dek).Name);
        }

        new static public Dek Create(string hashName)
        {
            return (Dek)HashAlgorithmFactory.Create(hashName);
        }

        public override void Initialize()
        {
            hash = seed;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (hash == 0)
            {
                hash = (uint)cbSize;
            }

            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                hash = ((hash << 5) ^ (hash >> 27)) ^ array[i];
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
