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
namespace Keeg.Crypto.Common
{
    internal static class ByteSwap
    {
        public static ushort Swap(ushort value)
        {
            return (ushort)(((value >> 8) & 0x00FF) | ((value << 8) & 0xFF00));
        }

        public static short Swap(short value)
        {
            return (short)Swap((ushort)value);
        }

        public static uint Swap(uint value)
        {
            uint x = ((value >> 16) & 0x0000FFFF) | ((value << 16) & 0xFFFF0000);
            return ((x & 0xFF00FF00) >> 8 | (x & 0x00FF00FF) << 8);
        }

        public static int Swap(int value)
        {
            return (int)Swap((uint)value);
        }

        public static ulong Swap(ulong value)
        {
            // swap adjacent 32-bit blocks
            ulong x = (value >> 32) | (value << 32);
            // swap adjacent 16-bit blocks
            x = ((x & 0xFFFF0000FFFF0000) >> 16) | ((x & 0x0000FFFF0000FFFF) << 16);
            // swap adjacent 8-bit blocks
            return ((x & 0xFF00FF00FF00FF00) >> 8) | ((x & 0x00FF00FF00FF00FF) << 8);
        }

        public static long Swap(long value)
        {
            return (long)Swap((ulong)value);
        }
    }
}
