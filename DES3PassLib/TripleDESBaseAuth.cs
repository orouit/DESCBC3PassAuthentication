/**
 * @author Olivier ROUIT
 * 
 * @license CPL, CodeProject license 
 */

using Core.Utility;
using System;
using System.Security.Cryptography;

namespace Core.Security
{
    public abstract class TripleDESBaseAuth : IKeySupport
    {
        protected readonly byte[] IV;
        protected const int RND_SIZE = 8;
        protected const int SESSION_KEY_SIZE = 16;
        protected const int IV_SIZE = 8;

        protected SymmetricAlgorithm symmetricCryptoAlgo = new TripleDESCryptoServiceProvider();
        protected ICryptoTransform encryptor;
        protected ICryptoTransform decryptor;
        protected byte[] rndA;
        protected byte[] rndB;
        protected bool authenticated = false;
        protected byte[] weakKey = null;

        protected RandomNumberGenerator randomGenerator;

        #region Constructors

        protected TripleDESBaseAuth()
        {
            IV = new byte[IV_SIZE];
            ByteArray.Fill(IV, 0);
            symmetricCryptoAlgo.KeySize = 128;  // Mode 2
            symmetricCryptoAlgo.Padding = PaddingMode.Zeros;
            symmetricCryptoAlgo.Mode = CipherMode.CBC;
            symmetricCryptoAlgo.IV = IV;

            randomGenerator = RNGCryptoServiceProvider.Create();

            encryptor = symmetricCryptoAlgo.CreateEncryptor();
            decryptor = symmetricCryptoAlgo.CreateDecryptor();
        }

        protected TripleDESBaseAuth(byte[] key)
            : this()
        {
            if (ByteArray.IsSetOf(key))
            {
                symmetricCryptoAlgo = new TripleDESCryptoServiceProvider();
                weakKey = key;
                symmetricCryptoAlgo.Padding = PaddingMode.Zeros;
                symmetricCryptoAlgo.Mode = CipherMode.CBC;
                symmetricCryptoAlgo.IV = IV;

                encryptor = ((TripleDESCryptoServiceProvider)symmetricCryptoAlgo).CreateWeakEncryptor(key, IV);
                decryptor = ((TripleDESCryptoServiceProvider)symmetricCryptoAlgo).CreateWeakDecryptor(key, IV);
            }
            else
            {
                symmetricCryptoAlgo.Key = key;

                // Recreate the encryptor and decryptor
                encryptor = symmetricCryptoAlgo.CreateEncryptor();
                decryptor = symmetricCryptoAlgo.CreateDecryptor();
            }
        }

        #endregion

        public byte[] Key
        {
            get
            {
                return (weakKey == null)
                    ? symmetricCryptoAlgo.Key
                    : weakKey;
            }
        }

        protected bool CompareRndWithRndr(byte[] rnd, byte[] rndr)
        {
            byte[] tmpRndr = ByteArray.RotateLeft(rnd);
            return ByteArray.AreSame(rndr, tmpRndr);
        }

        public bool TryGetSessionKey(out byte[] key)
        {
            bool ret = false;
            key = null;
            if (authenticated)
            {
                key = new byte[SESSION_KEY_SIZE];

                Buffer.BlockCopy(rndA, 0, key, 0, 4);
                Buffer.BlockCopy(rndB, 0, key, 4, 4);
                Buffer.BlockCopy(rndA, 4, key, 8, 4);
                Buffer.BlockCopy(rndB, 4, key, 12, 4);

                ret = true;
            }

            return ret;
        }
    }
}
