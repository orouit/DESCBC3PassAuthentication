/**
 * @author Olivier ROUIT
 * 
 * @license CPL, CodeProject license 
 */

namespace Core.Security
{
    /// <summary>
    /// This interface provides simple functions related to the Keys of a 3DES authentication for a
    /// DESFire
    /// </summary>
    interface IKeySupport
    {
        /// <summary>
        /// Gets the TripleDES key bytes
        /// </summary>
        byte[] Key { get; }

        /// <summary>
        /// Try to get the session key created when a 3DES DESFire authentication is successful
        /// </summary>
        /// <param name="key">The 16 bytes session key</param>
        /// <returns>true if key available, false otherwise</returns>
        bool TryGetSessionKey(out byte[] key);
    }
}
