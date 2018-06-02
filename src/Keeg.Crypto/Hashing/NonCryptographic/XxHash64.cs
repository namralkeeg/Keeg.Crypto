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
using Keeg.Crypto.Common;

namespace Keeg.Crypto.Hashing.NonCryptographic
{
    /// <summary>
    /// XXHash (64 bit), based on Yann Collet's descriptions, see http://cyan4973.github.io/xxHash/
    /// </summary>
    public sealed class XxHash64 : HashAlgorithm
    {
        #region Constants
        // magic constants :-)
        private const ulong Prime1 = 11400714785074694791ul;
        private const ulong Prime2 = 14029467366897019727ul;
        private const ulong Prime3 = 1609587929392839161ul;
        private const ulong Prime4 = 9650029242287828579ul;
        private const ulong Prime5 = 2870177450012600261ul;
        // temporarily store up to 31 bytes between multiple add() calls
        private const int MaxBufferSize = 31 + 1;
        #endregion

        #region Instance Fields
        private ulong seed;
        private int bufferSize;
        private ulong totalLength;
        // internal state and temporary buffer
        private ulong[] state = new ulong[4];
        private byte[] buffer = new byte[MaxBufferSize];
        #endregion

        public XxHash64()
        {
            HashSizeValue = 64;
            Seed = 0;
            Initialize();
        }

        public static new XxHash64 Create()
        {
            return Create(typeof(XxHash64).Name);
        }

        public static new XxHash64 Create(string hashName)
        {
            return (XxHash64)HashAlgorithmFactory.Create(hashName);
        }

        public ulong Seed { get => seed; set => seed = value; }

        public override void Initialize()
        {
            state[0] = seed + Prime1 + Prime2;
            state[1] = seed + Prime2;
            state[2] = seed;
            state[3] = seed - Prime1;
            bufferSize = 0;
            totalLength = 0;

            Array.Clear(buffer, 0, buffer.Length);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int length = cbSize;
            totalLength += (ulong)length;
            int current = ibStart;

            // unprocessed old data plus new data still fit in temporary buffer ?
            if (bufferSize + length < MaxBufferSize)
            {
                // just add new data
                Buffer.BlockCopy(array, current, buffer, bufferSize, length);
                bufferSize += length;
            }
            else
            {
                int stop = (ibStart + cbSize);
                int stopBlock = stop - MaxBufferSize;

                // copying state to local variables helps optimizer A LOT (For C++, not sure for C#)
                // TODO: Check performance of this.
                ulong s0 = state[0], s1 = state[1], s2 = state[2], s3 = state[3];

                // some data left from previous update ?
                if (bufferSize > 0)
                {
                    // make sure temporary buffer is full (32 bytes)
                    Buffer.BlockCopy(array, current, buffer, bufferSize, MaxBufferSize - bufferSize);
                    current += MaxBufferSize - bufferSize;
                    bufferSize = MaxBufferSize;

                    // process these 32 bytes (4x8)
                    Process32(buffer, 0, ref s0, ref s1, ref s2, ref s3);
                }

                // 32 bytes at once
                while (current <= stopBlock)
                {
                    // local variables s0..s3 instead of state[0]..state[3] are much faster
                    Process32(array, current, ref s0, ref s1, ref s2, ref s3);
                    current += 32;
                }

                // copy back
                state[0] = s0; state[1] = s1; state[2] = s2; state[3] = s3;

                bufferSize = (stop - current);
                // copy remainder to temporary buffer
                Buffer.BlockCopy(array, current, buffer, 0, (int)bufferSize);
            }
        }

        protected override byte[] HashFinal()
        {
            // fold 256 bit state into one single 64 bit value
            ulong result;
            if (totalLength >= MaxBufferSize)
            {
                result = state[0].Rol(1) +
                         state[1].Rol(7) +
                         state[2].Rol(12) +
                         state[3].Rol(18);
                result = (result ^ ((0 + state[0] * Prime2).Rol(31) * Prime1)) * Prime1 + Prime4;
                result = (result ^ ((0 + state[1] * Prime2).Rol(31) * Prime1)) * Prime1 + Prime4;
                result = (result ^ ((0 + state[2] * Prime2).Rol(31) * Prime1)) * Prime1 + Prime4;
                result = (result ^ ((0 + state[3] * Prime2).Rol(31) * Prime1)) * Prime1 + Prime4;
            }
            else
            {
                // internal state wasn't set in add(), therefore original seed is still stored in state2
                result = state[2] + Prime5;
            }

            result += totalLength;

            // at least 8 bytes left ? => eat 8 bytes per step
            int currentByte = 0;
            for (; currentByte + 8 <= bufferSize; currentByte += 8)
            {
                result = (result ^ ProcessSingle(0, BitConverterEndian.ToUInt64LE(buffer, currentByte)))
                    .Rol(27) * Prime1 + Prime4;
            }

            // 4 bytes left ? => eat those
            if (currentByte + 4 <= bufferSize)
            {
                result = (result ^ BitConverterEndian.ToUInt32LE(buffer, currentByte) * Prime1)
                    .Rol(23) * Prime2 + Prime3;
                currentByte += 4;
            }

            // take care of remaining 0..3 bytes, eat 1 byte per step
            while (currentByte != bufferSize)
            {
                result = (result ^ buffer[currentByte++] * Prime5).Rol(11) * Prime1;
            }

            // mix bits
            result ^= result >> 33;
            result *= Prime2;
            result ^= result >> 29;
            result *= Prime3;
            result ^= result >> 32;

            return BitConverter.GetBytes(result);
        }

        private ulong ProcessSingle(ulong previous, ulong input)
        {
            return (previous + input * Prime2).Rol(31) * Prime1;
        }

        private void Process32(byte[] block, int startIndex, ref ulong state0, ref ulong state1, ref ulong state2, 
            ref ulong state3)
        {
            unchecked
            {
                state0 = (state0 + BitConverterEndian.ToUInt64LE(block, startIndex + 0 * sizeof(ulong)) * Prime2).Rol(31) * Prime1;
                state1 = (state1 + BitConverterEndian.ToUInt64LE(block, startIndex + 1 * sizeof(ulong)) * Prime2).Rol(31) * Prime1;
                state2 = (state2 + BitConverterEndian.ToUInt64LE(block, startIndex + 2 * sizeof(ulong)) * Prime2).Rol(31) * Prime1;
                state3 = (state3 + BitConverterEndian.ToUInt64LE(block, startIndex + 3 * sizeof(ulong)) * Prime2).Rol(31) * Prime1;
            }
        }
    }
}
