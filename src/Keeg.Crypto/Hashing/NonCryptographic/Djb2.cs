using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

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
