namespace Keeg.Crypto.Encryption
{
    /// <summary>
    /// This enum represents the cypher mode to operate as.
    /// Not all implementations will support all modes.
    /// </summary>
    public enum CypherMode
    {
        /// <summary>
        /// Cypher Block Chaining encrypts each block of data in succession 
        /// so that any changes in the data will result in a completly different ciphertext.
        /// </summary>
        CBC = 1,
        /// <summary>
        /// Electronic Code Book mode encrypts each block of data with the same key, 
        /// so patterns in a large set of data will be visible. 
        /// </summary>
        ECB = 2,
        /// <summary>
        /// Output Feedback
        /// </summary>
        OFB = 3,
        /// <summary>
        /// Cypher Feedback
        /// </summary>
        CFB = 4,
        /// <summary>
        /// Ciphertext-Stealing
        /// </summary>
        CTS = 5,
        /// <summary>
        /// CTR mode uses an IV and a counter to encrypt each block individually.
        /// </summary>
        CTR = 6,
    }
}
