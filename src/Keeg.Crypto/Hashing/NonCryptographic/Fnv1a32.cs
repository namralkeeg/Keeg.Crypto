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

namespace Keeg.Crypto.Hashing.NonCryptographic
{
    /// <summary>
    /// Fowler/Noll/Vo or FNV1a 32 bit hash.
    /// See a detailed description at http://www.isthe.com/chongo/tech/comp/fnv/
    /// </summary>
    public sealed class Fnv1a32 : Fnv132
    {
        public Fnv1a32() : base() { }

        public static new Fnv1a32 Create()
        {
            return Create(typeof(Fnv1a32).Name);
        }

        public static new Fnv1a32 Create(string hashName)
        {
            return (Fnv1a32)HashAlgorithmFactory.Create(hashName);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                unchecked
                {
                    hash ^= array[i];
                    hash *= fnvPrime;
                }
            }
        }
    }
}
