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
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Keeg.Crypto.Common
{
    internal static class Utils
    {
        #region Instance Fields
        private static volatile RNGCryptoServiceProvider rng;
        #endregion

        static Utils()
        {
            rng = new RNGCryptoServiceProvider();
        }

        #region Properties
        internal static RNGCryptoServiceProvider StaticRNG => rng;
        #endregion

        #region Array Functions
        /// <summary>
        /// Generic function to create a shallow copy of a jagged array.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="source">The source array to copy from.</param>
        /// <returns>A shallow copy of the jagged array provided.</returns>
        internal static T[][] CopyArray<T>(T[][] source)
        {
            var length = source?.Length ?? throw new ArgumentNullException(nameof(source));
            var destination = new T[length][];

            for (var i = 0; i < length; ++i)
            {
                var innerArray = source[i];
                var innerLength = innerArray.Length;
                var newArray = new T[innerLength];
                Array.Copy(innerArray, newArray, innerLength);
                destination[i] = newArray;
            }

            return destination;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        internal static byte[] CopyByteArray(byte[] data)
        {
            var dataLength = data?.Length ?? throw new ArgumentNullException(nameof(data));

            var temp = new byte[dataLength];
            Buffer.BlockCopy(data, 0, temp, 0, dataLength);
            return temp;
        }
        #endregion

        #region Byte Conversion Functions
        /// <summary>
        /// Converts a hex character to it's numeric representation.
        /// </summary>
        /// <param name="c">The hex character to convert.</param>
        /// <returns>An <see cref="int"/> representing the hex character.</returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// Must be in the range 0..9, a..z, A..Z
        /// </exception>
        internal static int ParseNybble(char c)
        {
            if (c >= '0' && c <= '9')
            {
                return c - '0';
            }

            c = (char)(c & ~0x20);

            if (c >= 'A' && c <= 'F')
            {
                return c - ('A' - 10);
            }

            throw new ArgumentOutOfRangeException(nameof(c), $"Invalid nybble: {c}");
        }

        /// <summary>
        /// Converts a hex string to an equivalent byte array.
        /// </summary>
        /// <param name="hexString">String representing the hex to be conveted.</param>
        /// <returns>A <see cref="byte[]"/> array converted from the provided hex string.</returns>
        /// <exception cref="ArgumentException">The input must have an even number of characters.</exception>
        internal static byte[] HexToBytes(string hexString)
        {
            if ((hexString.Length & 1) != 0)
            {
                throw new ArgumentException("Input must have even number of characters");
            }
            int length = hexString.Length / 2;
            byte[] ret = new byte[length];
            int high, low;
            for (int i = 0, j = 0; i < length; i++)
            {
                high = ParseNybble(hexString[j++]);
                low = ParseNybble(hexString[j++]);
                ret[i] = (byte)((high << 4) | low);
            }

            return ret;
        }

        /// <summary>
        /// Converts a byte array to an equivalent hex string.
        /// </summary>
        /// <param name="data">Byte array to convert.</param>
        /// <param name="toLowerCase">If the hex characters should be upper or lowercase.</param>
        /// <returns>A <see cref="string"/> of hex characters representing the input byte array.</returns>
        internal static string BytesToHex(byte[] data, bool toLowerCase = false)
        {
            byte addByte = (toLowerCase) ? (byte)0x57 : (byte)0x37;
            int length = data.Length;
            char[] c = new char[length * 2];
            byte b;

            for (int i = 0; i < length; ++i)
            {
                b = ((byte)(data[i] >> 4));
                c[i * 2] = (char)(b > 9 ? b + addByte : b + 0x30);

                b = ((byte)(data[i] & 0xF));
                c[i * 2 + 1] = (char)(b > 9 ? b + addByte : b + 0x30);
            }

            return new string(c);
        }

        //internal static ushort BytesToWordBE(byte[] data, int offset)
        //{
        //    return (ushort)
        //        (
        //        (data[offset] << 8) | 
        //        (data[offset + 1])
        //        );
        //}

        //internal static void WordToBytesBE(ushort word, byte[] data, int offset)
        //{
        //    data[offset    ] = (byte)((word >> 8) & 0xFFu);
        //    data[offset + 1] = (byte)(word & 0xFFu);
        //}

        //internal static uint BytesToDWordBE(byte[] data, int offset)
        //{
        //    return (uint)
        //        (
        //        (data[offset] << 24) | 
        //        (data[offset + 1] << 16) | 
        //        (data[offset + 2] << 8) | 
        //        (data[offset + 3])
        //        );
        //}

        //internal static void DWordToBytesBE(uint dword, byte[] data, int offset)
        //{
        //    data[offset] = (byte)((dword >> 24) & 0xFF);
        //    data[offset + 1] = (byte)((dword >> 16) & 0xFF);
        //    data[offset + 2] = (byte)((dword >> 8) & 0xFF);
        //    data[offset + 3] = (byte)(dword & 0xFF);
        //}

        //internal static ulong BytesToQuadWordBE(byte[] data, int offset = 0)
        //{
        //    return (ulong)
        //        (
        //        (data[offset] << 56) |
        //        (data[offset + 1] << 48) |
        //        (data[offset + 2] << 40) |
        //        (data[offset + 3] << 32) |
        //        (data[offset + 4] << 24) |
        //        (data[offset + 5] << 16) |
        //        (data[offset + 6] << 8) |
        //        (data[offset + 7])
        //        );
        //}

        //internal static void QuadWordToBytesBE(ulong qword, byte[] data, int offset = 0)
        //{
        //    data[offset] = (byte)((qword >> 56) & 0xFF);
        //    data[offset + 1] = (byte)((qword >> 48) & 0xFF);
        //    data[offset + 2] = (byte)((qword >> 40) & 0xFF);
        //    data[offset + 3] = (byte)((qword >> 32) & 0xFF);
        //    data[offset + 4] = (byte)((qword >> 24) & 0xFF);
        //    data[offset + 5] = (byte)((qword >> 16) & 0xFF);
        //    data[offset + 6] = (byte)((qword >> 08) & 0xFF);
        //    data[offset + 7] = (byte)(qword & 0xFF);
        //}
        #endregion
    }
}
