/**
 * @author Olivier ROUIT
 * 
 * @license CPL, CodeProject license 
 */

using Core.Utility;
using System;

namespace Core.Security
{
    public class PICC : TripleDESBaseAuth, IPICCAuthentication
    {
        public PICC()
            : base()
        {
        }

        public byte[] AuthenticateStep1(int keyNo = 0)
        {
            Console.WriteLine();
            Console.WriteLine("PICC::AuthenticateStep1");
            rndA = null;
            // Generate rndA
            rndB = new byte[RND_SIZE];
            randomGenerator.GetNonZeroBytes(rndB);

            Console.WriteLine(string.Format(">> RndB:              {0}", ByteArray.ToString(rndB)));

            // Encypher with TripleDES
            byte[] encRndB = encryptor.TransformFinalBlock(rndB, 0, RND_SIZE);
            Console.WriteLine(string.Format(">> Enc(RndB):         {0}", ByteArray.ToString(encRndB)));

            return encRndB;
        }

        public bool AuthenticateStep3(byte[] decRndABr, out byte[] encRndAr)
        {
            Console.WriteLine();
            Console.WriteLine("PICC::AuthenticateStep3");
            authenticated = false;
            encRndAr = null;

            // Get encRndABr
            byte[] encRndABr = encryptor.TransformFinalBlock(decRndABr, 0, decRndABr.Length);
            Console.WriteLine(string.Format(">> RnbA + RndB':      {0}", ByteArray.ToString(encRndABr)));

            byte[] rndBr = new byte[RND_SIZE];
            Buffer.BlockCopy(encRndABr, RND_SIZE, rndBr, 0, RND_SIZE);
            Console.WriteLine(string.Format(">> RndB':             {0}", ByteArray.ToString(rndBr)));

            if (CompareRndWithRndr(rndB, rndBr))
            {
                rndA = new byte[RND_SIZE];
                Buffer.BlockCopy(encRndABr, 0, rndA, 0, RND_SIZE);
                Console.WriteLine(string.Format(">> RndA:              {0}", ByteArray.ToString(rndA)));

                // Rotate RndA => RndAr and encrypt it
                byte[] rndAr = ByteArray.RotateLeft(rndA);
                Console.WriteLine(string.Format(">> RndA':             {0}", ByteArray.ToString(rndAr)));

                encRndAr = encryptor.TransformFinalBlock(rndAr, 0, RND_SIZE);
                Console.WriteLine(string.Format(">> Enc(RndA'):        {0}", ByteArray.ToString(encRndAr)));

                authenticated = true;
            }

            return authenticated;
        }
    }
}
