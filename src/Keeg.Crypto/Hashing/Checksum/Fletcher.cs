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
using System.Collections.Generic;
using System.Security.Cryptography;
using Keeg.Crypto.Common;

namespace Keeg.Crypto.Hashing.Checksum
{
    /// <summary>
    /// The Fletcher checksum is an algorithm for computing a position-dependent checksum devised by John G. Fletcher.
    /// https://en.wikipedia.org/wiki/Fletcher%27s_checksum
    /// </summary>
    public sealed class Fletcher : HashAlgorithm
    {
        private int bytesPerCycle;
        private ulong modValue;
        private ulong sum1;
        private ulong sum2;
        private BitSize bitSize;

        public override int HashSize => (int)bitSize;
        public BitSize BitSize
        {
            get => bitSize;
            set
            {
                bitSize = value;
                bytesPerCycle = (int)bitSize / 16;
                modValue = (ulong)(Math.Pow(2, 8 * bytesPerCycle) - 1);
            }
        }

        public Fletcher()
        {
            BitSize = BitSize.Bits32;
            Initialize();
        }

        public override void Initialize()
        {
            sum1 = 0;
            sum2 = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            foreach (ulong block in Blockify(array, bytesPerCycle))
            {
                sum1 = (sum1 + block) % modValue;
                sum2 = (sum2 + sum1) % modValue;
            }
        }

        protected override byte[] HashFinal()
        {
            ulong hash = (sum1 + (sum2 * (modValue + 1)));
            switch (bitSize)
            {
                case BitSize.Bits16:
                    return BitConverter.GetBytes((ushort)hash);
                case BitSize.Bits32:
                    return BitConverter.GetBytes((uint)hash);
                case BitSize.Bits64:
                    return BitConverter.GetBytes(hash);
                default:
                    return BitConverter.GetBytes(hash);
            }
        }

        private IEnumerable<ulong> Blockify(byte[] inputAsBytes, int blockSize)
        {
            int i = 0;

            // Using an unsigned type is important - otherwise an arithmetic overflow will result
            ulong block = 0;

            // Run through all the bytes			
            while (i < inputAsBytes.Length)
            {
                unchecked
                {
                    // Keep stacking them side by side by shifting left and OR-ing				
                    block = block << 8 | inputAsBytes[i];
                }

                i++;

                // Return a block whenever we meet a boundary
                if (i % blockSize == 0 || i == inputAsBytes.Length)
                {
                    yield return block;

                    // Set to 0 for next iteration
                    block = 0;
                }
            }
        }
    }
}
