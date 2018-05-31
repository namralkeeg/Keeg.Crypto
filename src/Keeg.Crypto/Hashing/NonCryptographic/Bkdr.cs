using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Keeg.Crypto.Hashing.NonCryptographic
{
    /// <summary>
    /// This hash function comes from Brian Kernighan and Dennis Ritchie's book "The C Programming Language".
    /// </summary>
    public sealed class Bkdr : HashAlgorithm
    {
        private uint seed;
        private uint hash;

        public Bkdr()
        {
            /// 31 131 1313 13131 131313 etc..
            seed = 131u;
            Initialize();
        }

        new static public Bkdr Create()
        {
            return Create(typeof(Bkdr).Name);
        }

        new static public Bkdr Create(string hashName)
        {
            return (Bkdr)HashAlgorithmFactory.Create(hashName);
        }

        public override void Initialize()
        {
            hash = seed;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                hash = (hash * seed) + array[i];
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }

        public uint Seed { get => seed; set => seed = value; }
    }
}
