namespace Keeg.Crypto.Encryption
{
    /// <summary>
    /// This enum represents the padding method to use for filling out short blocks.
    /// </summary>
    public enum PaddingMode
    {
        /// <summary>
        /// No padding (whole blocks required).
        /// </summary>
        None = 1,
        /// <summary>
        /// The padding mode defined in RFC 2898, Section 6.1.1, Step 4, 
        /// generalized to whatever block size is required.
        /// </summary>
        PKCS7 = 2,
        /// <summary>
        /// Pad with zero bytes to fill out the last block.
        /// </summary>
        Zeros = 3,
        /// <summary>
        /// Fills the bytes with zeros and puts the number of padding bytes in the last byte.
        /// </summary>
        ANSIX923 = 4,
        /// <summary>
        /// The same as PKCS5 except that it fills the bytes before the last one with random bytes.
        /// </summary>
        ISO10126 = 5,
        PKCS5 = 6,
    }
}
