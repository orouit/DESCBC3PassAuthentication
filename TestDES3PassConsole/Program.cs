/**
 * @author Olivier ROUIT
 * 
 * @license CPL, CodeProject license 
 */

using Core.Security;
using Core.Utility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace TestDESCBC3PassAuthentication
{
    class Program
    {
        static void Main(string[] args)
        {
            Test3DES_3PassAuthentication();
        }

        static void Test3DES()
        {
            TripleDESCryptoServiceProvider tripleDESCrypto = new TripleDESCryptoServiceProvider();
            tripleDESCrypto.KeySize = 128;
            tripleDESCrypto.Mode = CipherMode.CBC;
            tripleDESCrypto.Padding = PaddingMode.Zeros;
            tripleDESCrypto.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };

            RandomNumberGenerator random = RNGCryptoServiceProvider.Create();
            byte[] rnd = new byte[8];
            random.GetNonZeroBytes(rnd);

            ICryptoTransform encryptor = tripleDESCrypto.CreateEncryptor();
            byte[] encRnd = encryptor.TransformFinalBlock(rnd, 0, 8);

            TripleDESCryptoServiceProvider tripleDESCrypto2 = new TripleDESCryptoServiceProvider();
            tripleDESCrypto2.KeySize = 128;
            tripleDESCrypto2.Mode = CipherMode.CBC;
            tripleDESCrypto2.Padding = PaddingMode.Zeros;
            tripleDESCrypto2.IV = tripleDESCrypto.IV;
            tripleDESCrypto2.Key = tripleDESCrypto.Key;

            ICryptoTransform decryptor = tripleDESCrypto2.CreateDecryptor();
            byte[] decRnd = decryptor.TransformFinalBlock(encRnd, 0, 8);
        }

        static void Test3DES_3PassAuthentication()
        {
            PICC picc = new PICC();

            byte[] key = picc.Key;
            Console.WriteLine(string.Format(">> 3DES Key:          {0}", ByteArray.ToString(key)));

            byte[] encRndB = picc.AuthenticateStep1();

            //byte[] encRndB = ByteArray.Parse("2989B545BC7172A2");

            PCD pcd = new PCD(key);
            byte[] decRndABr = pcd.AuthenticateStep2(encRndB);
            string decRndABrStr = ByteArray.ToString(decRndABr);

            byte[] encRndAr;
            bool pcdAuthenticated = picc.AuthenticateStep3(decRndABr, out encRndAr);
            Console.WriteLine();
            if (pcdAuthenticated)
            {
                // PCD has been authenticated by the PICC
                Console.WriteLine("PCD authenticated by PICC");
                byte[] piccSessionKey;
                if (picc.TryGetSessionKey(out piccSessionKey))
                {
                    Console.WriteLine(string.Format(">> PICC SessionKey:   {0}", ByteArray.ToString(piccSessionKey)));
                }

                bool piccAuthenticated = pcd.AuthenticateStep4(encRndAr);
                Console.WriteLine();
                if (piccAuthenticated)
                {
                    Console.WriteLine("PICC authenticated by PCD");
                    byte[] pcdSessionKey;
                    if (pcd.TryGetSessionKey(out pcdSessionKey))
                    {
                        Console.WriteLine(string.Format(">> PCD SessionKey:    {0}", ByteArray.ToString(pcdSessionKey)));
                    }
                }
                else
                {
                    Console.WriteLine("PICC not authenticated by PCD");
                }
            }
            else
            {
                Console.WriteLine("PCD not authenticated by PICC");
            }
        }
    }
}
