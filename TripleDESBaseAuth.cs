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
        private readonly byte[] IV;
        protected const int RND_SIZE = 8;
        protected const int SESSION_KEY_SIZE = 16;
        protected const int IV_SIZE = 8;

        protected TripleDESCryptoServiceProvider tripleDESCrypto = new TripleDESCryptoServiceProvider();
        protected ICryptoTransform encryptor;
        protected ICryptoTransform decryptor;
        protected byte[] rndA;
        protected byte[] rndB;
        protected bool authenticated = false;

        protected RandomNumberGenerator randomGenerator;

        #region Constructors

        protected TripleDESBaseAuth()
        {
            IV = new byte[IV_SIZE];
            ByteArray.Fill(IV, 0);
            tripleDESCrypto.KeySize = 128;  // Mode 2
            tripleDESCrypto.Padding = PaddingMode.Zeros;
            tripleDESCrypto.Mode = CipherMode.CBC;
            tripleDESCrypto.IV = IV;

            randomGenerator = RNGCryptoServiceProvider.Create();

            encryptor = tripleDESCrypto.CreateEncryptor();
            decryptor = tripleDESCrypto.CreateDecryptor();
        }

        protected TripleDESBaseAuth(byte[] key)
            : this()
        {
            tripleDESCrypto.Key = key;

            // Recreate the encryptor and decryptor
            encryptor = tripleDESCrypto.CreateEncryptor();
            decryptor = tripleDESCrypto.CreateDecryptor();
        }

        #endregion

        public byte[] Key
        {
            get
            {
                return tripleDESCrypto.Key;
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
