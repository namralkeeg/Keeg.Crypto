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
    /// Bob Jenkins One-at-a-Time hash
    /// http://www.burtleburtle.net/bob/hash/doobs.html
    /// </summary>
    public sealed class Joaat : HashAlgorithm
    {
        private uint hash;

        public Joaat()
        {
            HashSizeValue = 32;
            Initialize();
        }

        public static new Joaat Create()
        {
            return Create(typeof(Joaat).Name);
        }

        public static new Joaat Create(string hashName)
        {
            return (Joaat)HashAlgorithmFactory.Create(hashName);
        }

        public override void Initialize()
        {
            hash = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                unchecked
                {
                    hash += array[i];
                    hash += (hash << 10);
                    hash ^= (hash >> 6);
                }
            }
        }

        protected override byte[] HashFinal()
        {
            unchecked
            {
                hash += (hash << 3);
                hash ^= (hash >> 11);
                hash += (hash << 15);
            }

            return BitConverter.GetBytes(hash);
        }
    }
}
