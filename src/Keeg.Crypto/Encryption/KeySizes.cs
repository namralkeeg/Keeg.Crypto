namespace Keeg.Crypto.Encryption
{
    /// <summary>
    /// 
    /// </summary>
    public sealed class KeySizes
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="minSize"></param>
        /// <param name="maxSize"></param>
        /// <param name="skipSize"></param>
        public KeySizes(int minSize, int maxSize, int skipSize)
        {
            MinSize = minSize;
            MaxSize = maxSize;
            SkipSize = skipSize;
        }

        public int MinSize { get; }
        public int MaxSize { get; }
        public int SkipSize { get; }
    }
}
