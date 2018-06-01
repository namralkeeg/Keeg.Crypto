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
    /// Algorithm by Paul Hsieh
    /// </summary>
    public sealed class SuperFast : HashAlgorithm
    {
        private uint hash;

        public SuperFast()
        {
            HashSizeValue = 32;
            Initialize();
        }

        public static new SuperFast Create()
        {
            return Create(typeof(SuperFast).Name);
        }

        public static new SuperFast Create(string hashName)
        {
            return (SuperFast)HashAlgorithmFactory.Create(hashName);
        }

        public override void Initialize()
        {
            hash = 0;
        }

        private ushort Get16Bits(byte[] array, int pos)
        {
            return (ushort)((array[pos + 1] << 8) + array[pos]);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int length = cbSize;
            uint temp;
            int rem = length & 3;
            int pos = ibStart;

            if (hash == 0)
            {
                hash = (uint)length;
            }

            unchecked
            {
                length >>= 2;

                for (; length > 0; length--)
                {
                    hash += Get16Bits(array, pos);
                    pos += 2;
                    temp = (uint)(Get16Bits(array, pos) << 11) ^ hash;
                    hash = (hash << 16) ^ temp;
                    pos += 2;
                    hash += hash >> 11;
                }

                // Handle end cases
                switch (rem)
                {
                    case 3:
                        hash += Get16Bits(array, pos);
                        pos += 2;
                        hash ^= hash << 16;
                        hash ^= (byte)(array[pos] << 18);
                        hash += hash >> 11;
                        break;
                    case 2:
                        hash += Get16Bits(array, pos);
                        hash ^= hash << 11;
                        hash += hash >> 17;
                        break;
                    case 1:
                        hash += array[pos];
                        hash ^= hash << 10;
                        hash += hash >> 1;
                        break;
                    default:
                        break;
                }
            }
        }

        protected override byte[] HashFinal()
        {
            unchecked
            {
                // Force "avalanching" of final 127 bits
                hash ^= hash << 3;
                hash += hash >> 5;
                hash ^= hash << 4;
                hash += hash >> 17;
                hash ^= hash << 25;
                hash += hash >> 6;
            }

            return BitConverter.GetBytes(hash);
        }
    }
}
