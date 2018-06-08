using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Keeg.Crypto.Common;

namespace Keeg.Crypto.Encryption
{
    /// <summary>
    /// 
    /// </summary>
    public abstract class SymmetricAlgorithm : IDisposable, ICryptoTransform
    {
        #region Fields
        protected int m_blockSize;
        protected int m_feedbackSize;
        protected byte[] m_iv;
        protected byte[] m_key;
        protected int m_keySize;
        protected CypherMode m_cypherMode;
        protected PaddingMode m_paddingMode;
        protected TransformMode m_transformMode;
        protected KeySizes[] m_legalBlockSizes;
        protected KeySizes[] m_legalKeySizes;
        protected readonly HashSet<CypherMode> m_legalCypherModes = new HashSet<CypherMode>();
        #endregion

        #region Constructors
        protected SymmetricAlgorithm()
        {
            m_paddingMode = PaddingMode.PKCS7;
            Mode = CypherMode.CBC;
            m_transformMode = TransformMode.Encrypt;
        }

        protected SymmetricAlgorithm(byte[] key) : this()
        {
            Key = key;
        }

        protected SymmetricAlgorithm(string key) : this(Utils.HexToBytes(key))
        { }

        protected SymmetricAlgorithm(byte[] key, byte[] iv) : this()
        {
            Key = key;
            IV = iv;
        }

        protected SymmetricAlgorithm(string key, string iv) 
            : this(Utils.HexToBytes(key), Utils.HexToBytes(iv))
        { }
        #endregion

        #region Properies
        public virtual int BlockSize
        {
            get => m_blockSize;
            set
            {
                for (int i = 0; i < m_legalBlockSizes.Length; i++)
                {
                    // If a cipher has only one valid block size, MinSize == MaxSize and SkipSize will be 0
                    if (m_legalBlockSizes[i].SkipSize == 0)
                    {
                        if (m_legalBlockSizes[i].MinSize == value)
                        {
                            m_blockSize = value;
                            m_iv = null;
                            return;
                        }
                    }
                    else
                    {
                        for (int j = m_legalBlockSizes[i].MinSize; j <= m_legalBlockSizes[i].MaxSize; 
                            j += m_legalBlockSizes[i].SkipSize)
                        {
                            if (j == value)
                            {
                                if (m_blockSize != value)
                                {
                                    m_blockSize = value;
                                    m_iv = null;
                                    return;
                                }
                            }
                        }
                    }
                }

                throw new ArgumentException("Invalid Block Size", nameof(BlockSize));
            }
        }

        public virtual int FeedbackSize
        {
            get => m_feedbackSize;
            set
            {
                if ((value <= 0) || (value > m_blockSize) || (value % 8) != 0)
                {
                    throw new ArgumentException("Invalid Feedback Size.", nameof(FeedbackSize));
                }

                m_feedbackSize = value;
            }
        }

        public virtual byte[] IV
        {
            get
            {
                if (m_iv == null)
                {
                    GenerateIV();
                }

                return Utils.CopyByteArray(m_iv);
            }

            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }
                if (value.Length != m_blockSize / 8)
                {
                    throw new ArgumentException("Invalid IV Size.", nameof(IV));
                }

                m_iv = Utils.CopyByteArray(value);
            }
        }

        public virtual byte[] Key
        {
            get
            {
                if (m_key == null)
                {
                    GenerateKey();
                }

                return Utils.CopyByteArray(m_key);
            }

            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }
                if (!ValidKeySize(value.Length * 8))
                {
                    throw new ArgumentException("Invalid Key Size.", nameof(Key));
                }

                // Do any assignment and setup with the provided key.
                SetKey(value);
                // must convert bytes to bits
                m_keySize = value.Length * 8;
            }
        }

        public virtual int KeySize
        {
            get => m_keySize;
            set
            {
                if (!ValidKeySize(value))
                {
                    throw new ArgumentException("Invalid Key Size", nameof(KeySize));
                }

                m_keySize = value;
                m_key = null;
            }
        }

        public virtual CypherMode Mode
        {
            get => m_cypherMode;
            set
            {
                if (!LegalCypherModes.Contains(value))
                {
                    throw new ArgumentException("Invalid Cypher Mode.", nameof(value));
                }

                m_cypherMode = value;
            }
        }

        public virtual PaddingMode Padding { get => m_paddingMode; set => m_paddingMode = value; }
        public virtual TransformMode Transform { get => m_transformMode; set => m_transformMode = value; }
        public virtual CypherMode[] LegalCypherModes { get => m_legalCypherModes.ToArray(); }
        public virtual KeySizes[] LegalKeySizes { get => (KeySizes[])m_legalKeySizes.Clone(); }
        public virtual KeySizes[] LegalBlockSizes { get => (KeySizes[])m_legalBlockSizes.Clone(); }
        public virtual int InputBlockSize { get => m_blockSize / 8; }
        public virtual int OutputBlockSize { get => m_blockSize / 8; }
        public virtual bool CanTransformMultipleBlocks { get => true; }
        public virtual bool CanReuseTransform { get => true; }
        #endregion

        #region Functions
        /// <summary>
        /// Takes a bit length input and returns whether that length is a valid size according to <see cref="LegalKeySizes"/>
        /// </summary>
        /// <param name="bitLength">Size of the key in bits.</param>
        /// <returns>True if the given bit length is valid.</returns>
        public bool ValidKeySize(int bitLength)
        {
            if (m_legalKeySizes == null)
            {
                return false;
            }

            for (int i = 0; i < m_legalKeySizes.Length; i++)
            {
                // If a cipher has only one valid key size, MinSize == MaxSize and SkipSize will be 0
                if (m_legalKeySizes[i].SkipSize == 0)
                {
                    if (m_legalKeySizes[i].MinSize == bitLength) // MinSize = MaxSize
                    {
                        return true;
                    }
                }
                else
                {
                    for (int j = m_legalKeySizes[i].MinSize; j <= m_legalKeySizes[i].MaxSize; 
                        j += m_legalKeySizes[i].SkipSize)
                    {
                        if (j == bitLength)
                        {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// 
        /// </summary>
        public abstract void GenerateKey();

        /// <summary>
        /// 
        /// </summary>
        public abstract void GenerateIV();

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        protected virtual void SetKey(byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            if (!ValidKeySize(key.Length * 8))
            {
                throw new ArgumentException("Invalid Key Size.", nameof(key));
            }

            m_key = Utils.CopyByteArray(key);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        public virtual string Encrypt(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                throw new ArgumentNullException(nameof(text));
            }

            var bytes = Encoding.UTF8.GetBytes(text);
            var encrypted = Encrypt(bytes);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        public virtual string Decrypt(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                throw new ArgumentNullException(nameof(text));
            }

            var bytes = Convert.FromBase64String(text);
            var decrypted = Decrypt(bytes);
            return Encoding.UTF8.GetString(decrypted);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public virtual byte[] Encrypt(byte[] buffer)
        {
            return Encrypt(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public abstract byte[] Encrypt(byte[] buffer, int offset, int count);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public virtual byte[] Decrypt(byte[] buffer)
        {
            return Decrypt(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public abstract byte[] Decrypt(byte[] buffer, int offset, int count);

        /// <summary>
        /// <see cref="ICryptoTransform"/>
        /// </summary>
        /// <param name="inputBuffer"></param>
        /// <param name="inputOffset"></param>
        /// <param name="inputCount"></param>
        /// <param name="outputBuffer"></param>
        /// <param name="outputOffset"></param>
        /// <returns></returns>
        public abstract int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);

        /// <summary>
        /// <see cref="ICryptoTransform"/>
        /// </summary>
        /// <param name="inputBuffer"></param>
        /// <param name="inputOffset"></param>
        /// <param name="inputCount"></param>
        /// <returns></returns>
        public abstract byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);
        #endregion

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects).
                    if (m_key != null)
                    {
                        Array.Clear(m_key, 0, m_key.Length);
                        m_key = null;
                    }

                    if (m_iv != null)
                    {
                        Array.Clear(m_iv, 0, m_iv.Length);
                        m_iv = null;
                    }
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~SymmetricAlgorithm() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
        #endregion
    }
}
