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
    /// This algorithm is based on work by Peter J. Weinberger of AT&T Bell Labs.
    /// </summary>
    public sealed class Pjw : HashAlgorithm
    {
        private const uint BitsInUnsignedInt = 32;
        private const uint ThreeQuarters = ((BitsInUnsignedInt * 3) / 4);
        private const uint OneEighth = (BitsInUnsignedInt / 8);
        private const uint HighBits = (0xFFFFFFFFu << (int)(BitsInUnsignedInt - OneEighth));
        private uint hash;

        public Pjw()
        {
            HashSizeValue = 32;
            Initialize();
        }

        public static new Pjw Create()
        {
            return Create(typeof(Pjw).Name);
        }

        public static new Pjw Create(string hashName)
        {
            return (Pjw)HashAlgorithmFactory.Create(hashName);
        }

        public override void Initialize()
        {
            hash = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            uint test = 0;
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                unchecked
                {
                    hash = (hash << (int)OneEighth) + array[i];

                    test = hash & HighBits;
                    if (test != 0)
                    {
                        hash = ((hash ^ (test >> (int)ThreeQuarters)) & (~HighBits));
                    }
                }
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
