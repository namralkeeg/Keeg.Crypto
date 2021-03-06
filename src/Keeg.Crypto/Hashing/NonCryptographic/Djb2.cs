﻿#region Copyright
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
    /// An algorithm produced by Professor Daniel J. Bernstein.
    /// Originally introduced on the usenet newsgroup comp.lang.c.
    /// </summary>
    public sealed class Djb2 : HashAlgorithm
    {
        private const uint DefaultSeed = 5381u;
        private uint seed;
        private uint hash;

        public Djb2()
        {
            HashSizeValue = 32;
            Seed = DefaultSeed;
            Initialize();
        }

        new static public Djb2 Create()
        {
            return Create(typeof(Djb2).Name);
        }

        new static public Djb2 Create(string hashName)
        {
            return (Djb2)HashAlgorithmFactory.Create(hashName);
        }

        public uint Seed { get => seed; set => seed = value; }

        public override void Initialize()
        {
            hash = Seed;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                hash = ((hash << 5) + hash) + array[i]; /* hash * 33 + c */
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
