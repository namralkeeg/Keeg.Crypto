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

namespace Keeg.Crypto.Common
{
    internal static class BitConverterEndian
    {
        #region Get Bytes
        public static unsafe byte[] GetBytesBE(short value)
        {
            byte[] bytes = new byte[2];
            fixed (byte* pbyte = bytes)
            {
                *(pbyte + 0) = (byte)(value >> 8);
                *(pbyte + 1) = (byte)(value >> 0);
            }

            return bytes;
        }

        public static unsafe byte[] GetBytesBE(int value)
        {
            byte[] bytes = new byte[4];
            fixed (byte* pbyte = bytes)
            {
                *(pbyte + 0) = (byte)(value >> 24);
                *(pbyte + 1) = (byte)(value >> 16);
                *(pbyte + 2) = (byte)(value >>  8);
                *(pbyte + 3) = (byte)(value >>  0);
            }

            return bytes;
        }

        public static unsafe byte[] GetBytesBE(long value)
        {
            byte[] bytes = new byte[8];
            fixed (byte* pbyte = bytes)
            {
                *(pbyte + 0) = (byte)(value >> 56);
                *(pbyte + 1) = (byte)(value >> 48);
                *(pbyte + 2) = (byte)(value >> 40);
                *(pbyte + 3) = (byte)(value >> 32);
                *(pbyte + 3) = (byte)(value >> 24);
                *(pbyte + 3) = (byte)(value >> 16);
                *(pbyte + 3) = (byte)(value >>  8);
                *(pbyte + 3) = (byte)(value >>  0);
            }

            return bytes;
        }

        public static unsafe byte[] GetBytesBE(ushort value)
        {
            return GetBytesBE((short)value);
        }

        public static unsafe byte[] GetBytesBE(uint value)
        {
            return GetBytesBE((int)value);
        }

        public static unsafe byte[] GetBytesBE(ulong value)
        {
            return GetBytesBE((long)value);
        }

        public static unsafe byte[] GetBytesLE(short value)
        {
            byte[] bytes = new byte[2];
            fixed (byte* pbyte = bytes)
            {
                *(pbyte + 0) = (byte)(value >> 0);
                *(pbyte + 1) = (byte)(value >> 8);
            }

            return bytes;
        }

        public static unsafe byte[] GetBytesLE(int value)
        {
            byte[] bytes = new byte[4];
            fixed (byte* pbyte = bytes)
            {
                *(pbyte + 0) = (byte)(value >> 0);
                *(pbyte + 1) = (byte)(value >> 8);
                *(pbyte + 2) = (byte)(value >> 16);
                *(pbyte + 3) = (byte)(value >> 24);
            }

            return bytes;
        }

        public static unsafe byte[] GetBytesLE(long value)
        {
            byte[] bytes = new byte[8];
            fixed (byte* pbyte = bytes)
            {
                *(pbyte + 0) = (byte)(value >> 0);
                *(pbyte + 1) = (byte)(value >> 8);
                *(pbyte + 2) = (byte)(value >> 16);
                *(pbyte + 3) = (byte)(value >> 24);
                *(pbyte + 4) = (byte)(value >> 32);
                *(pbyte + 5) = (byte)(value >> 40);
                *(pbyte + 6) = (byte)(value >> 48);
                *(pbyte + 7) = (byte)(value >> 56);
            }

            return bytes;
        }

        public static unsafe byte[] GetBytesLE(ushort value)
        {
            return GetBytesLE((short)value);
        }

        public static unsafe byte[] GetBytesLE(uint value)
        {
            return GetBytesLE((int)value);
        }

        public static unsafe byte[] GetBytesLE(ulong value)
        {
            return GetBytesLE((long)value);
        }
        #endregion

        #region Set Bytes
        public static unsafe void SetBytesBE(short value, byte[] array, int startIndex)
        {
            if (array == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(short) <= array.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &array[startIndex])
            {
                *(pbyte + 0) = (byte)(value >> 8);
                *(pbyte + 1) = (byte)(value >> 0);
            }
        }

        public static unsafe void SetBytesBE(int value, byte[] array, int startIndex)
        {
            if (array == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(int) <= array.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &array[startIndex])
            {
                *(pbyte + 0) = (byte)(value >> 24);
                *(pbyte + 1) = (byte)(value >> 16);
                *(pbyte + 2) = (byte)(value >> 8);
                *(pbyte + 3) = (byte)(value >> 0);
            }
        }

        public static unsafe void SetBytesBE(long value, byte[] array, int startIndex)
        {
            if (array == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(long) <= array.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &array[startIndex])
            {
                *(pbyte + 0) = (byte)(value >> 56);
                *(pbyte + 1) = (byte)(value >> 48);
                *(pbyte + 2) = (byte)(value >> 40);
                *(pbyte + 3) = (byte)(value >> 32);
                *(pbyte + 4) = (byte)(value >> 24);
                *(pbyte + 5) = (byte)(value >> 16);
                *(pbyte + 6) = (byte)(value >> 8);
                *(pbyte + 7) = (byte)(value >> 0);
            }
        }

        public static unsafe void SetBytesBE(ushort value, byte[] array, int startIndex)
        {
            SetBytesBE((short)value, array, startIndex);
        }

        public static unsafe void SetBytesBE(uint value, byte[] array, int startIndex)
        {
            SetBytesBE((int)value, array, startIndex);
        }

        public static unsafe void SetBytesBE(ulong value, byte[] array, int startIndex)
        {
            SetBytesBE((long)value, array, startIndex);
        }

        public static unsafe void SetBytesLE(short value, byte[] array, int startIndex)
        {
            if (array == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(short) <= array.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &array[startIndex])
            {
                *(pbyte + 0) = (byte)(value >> 0);
                *(pbyte + 1) = (byte)(value >> 8);
            }
        }

        public static unsafe void SetBytesLE(int value, byte[] array, int startIndex)
        {
            if (array == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(int) <= array.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &array[startIndex])
            {
                *(pbyte + 0) = (byte)(value >> 0);
                *(pbyte + 1) = (byte)(value >> 8);
                *(pbyte + 2) = (byte)(value >> 16);
                *(pbyte + 3) = (byte)(value >> 24);
            }
        }

        public static unsafe void SetBytesLE(long value, byte[] array, int startIndex)
        {
            if (array == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(long) <= array.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &array[startIndex])
            {
                *(pbyte + 0) = (byte)(value >> 0);
                *(pbyte + 1) = (byte)(value >> 8);
                *(pbyte + 2) = (byte)(value >> 16);
                *(pbyte + 3) = (byte)(value >> 24);
                *(pbyte + 4) = (byte)(value >> 32);
                *(pbyte + 5) = (byte)(value >> 40);
                *(pbyte + 6) = (byte)(value >> 48);
                *(pbyte + 7) = (byte)(value >> 56);
            }
        }

        public static unsafe void SetBytesLE(ushort value, byte[] array, int startIndex)
        {
            SetBytesLE((short)value, array, startIndex);
        }

        public static unsafe void SetBytesLE(uint value, byte[] array, int startIndex)
        {
            SetBytesLE((int)value, array, startIndex);
        }

        public static unsafe void SetBytesLE(ulong value, byte[] array, int startIndex)
        {
            SetBytesLE((long)value, array, startIndex);
        }
        #endregion

        #region To Integer
        public static unsafe short ToInt16BE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(short) <= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &value[startIndex])
            {
                return (short)
                    (
                    (*(pbyte + 0) << 8) |
                    (*(pbyte + 1))
                    );
            }
        }

        public static unsafe int ToInt32BE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(int) <= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &value[startIndex])
            {
                return (int)
                    (
                    (*(pbyte + 0) << 24) |
                    (*(pbyte + 1) << 16) |
                    (*(pbyte + 2) << 8) |
                    (*(pbyte + 3))
                    );
            }
        }

        public static unsafe long ToInt64BE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(long) <= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &value[startIndex])
            {
                return (long)
                (
                (*(pbyte + 0) << 56) |
                (*(pbyte + 1) << 48) |
                (*(pbyte + 2) << 40) |
                (*(pbyte + 3) << 32) |
                (*(pbyte + 4) << 24) |
                (*(pbyte + 5) << 16) |
                (*(pbyte + 6) << 8) |
                (*(pbyte + 7))
                );
            }
        }

        public static unsafe ushort ToUInt16BE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(ushort) <= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            return (ushort)ToInt16BE(value, startIndex);
        }

        public static unsafe uint ToUInt32BE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(uint) <= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            return (uint)ToInt32BE(value, startIndex);
        }

        public static unsafe ulong ToUInt64BE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(ulong) <= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            return (ulong)ToInt64BE(value, startIndex);
        }

        public static unsafe short ToInt16LE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(short) <= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &value[startIndex])
            {
                return (short)
                    (
                    (*(pbyte + 0)) |
                    (*(pbyte + 1) << 8)
                    );
            }
        }

        public static unsafe int ToInt32LE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(int) <= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &value[startIndex])
            {
                return (int)
                    (
                    (*(pbyte + 0)) |
                    (*(pbyte + 1) << 8) |
                    (*(pbyte + 2) << 16) |
                    (*(pbyte + 3) << 24)
                    );
            }
        }

        public static unsafe long ToInt64LE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(long) <= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &value[startIndex])
            {
                return (long)
                (
                (*(pbyte + 0)) |
                (*(pbyte + 1) << 8) |
                (*(pbyte + 2) << 16) |
                (*(pbyte + 3) << 24) |
                (*(pbyte + 4) << 32) |
                (*(pbyte + 5) << 40) |
                (*(pbyte + 6) << 48) |
                (*(pbyte + 7) << 56)
                );
            }
        }

        public static unsafe ushort ToUInt16LE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(ushort) <= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            return (ushort)ToInt16LE(value, startIndex);
        }

        public static unsafe uint ToUInt32LE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(uint) <= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            return (uint)ToInt32LE(value, startIndex);
        }

        public static unsafe ulong ToUInt64LE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (startIndex + sizeof(ulong) <= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            return (ulong)ToInt64LE(value, startIndex);
        }
        #endregion
    }
}
