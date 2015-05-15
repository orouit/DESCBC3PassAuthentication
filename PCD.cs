/**
 * @author Olivier ROUIT
 * 
 * @license CPL, CodeProject license 
 */

using Core.Utility;
using System;

namespace Core.Security
{
    public class PCD : TripleDESBaseAuth, IPCDAuthentication
    {
        public PCD()
            : base()
        {
        }

        public PCD(byte[] key)
            : base(key)
        {
        }

        /// <summary>
        /// Calculate dec(rndA + rndBp)
        /// </summary>
        /// <param name="encRndB"></param>
        /// <returns></returns>
        public byte[] AuthenticateStep2(byte[] encRndB)
        {
            Console.WriteLine();
            Console.WriteLine("PCD::AuthenticateStep2");
            // Decrypt rndB
            rndB = decryptor.TransformFinalBlock(encRndB, 0, RND_SIZE);
            Console.WriteLine(string.Format(">> RndB:              {0}", ByteArray.ToString(rndB)));

            // Rotate left 8 bits
            byte[] rndBr = ByteArray.RotateLeft(rndB);
            Console.WriteLine(string.Format(">> RndB':             {0}", ByteArray.ToString(rndBr)));

            // Generate RndA
            rndA = new byte[RND_SIZE];
            randomGenerator.GetNonZeroBytes(rndA);
            Console.WriteLine(string.Format(">> RndA:              {0}", ByteArray.ToString(rndA)));

            // Create rndA + rndBr
            byte[] rndABr = ByteArray.Concatenate(rndA, rndBr);
            Console.WriteLine(string.Format(">> RndA + RndB':      {0}", ByteArray.ToString(rndABr)));

            // Use decypherment to create the cryptogram
            byte[] decRndABr = decryptor.TransformFinalBlock(rndABr, 0, rndABr.Length);
            Console.WriteLine(string.Format(">> Dec(RndA + RndB'): {0}", ByteArray.ToString(decRndABr)));

            return decRndABr;
        }

        public bool AuthenticateStep4(byte[] encRndAr)
        {
            Console.WriteLine();
            Console.WriteLine("PCD::AuthenticateStep4");
            // Decrypt rndAr
            byte[] decRndAr = decryptor.TransformFinalBlock(encRndAr, 0, RND_SIZE);
            Console.WriteLine(string.Format(">> RndA':             {0}", ByteArray.ToString(decRndAr)));

            authenticated = CompareRndWithRndr(rndA, decRndAr);
            return authenticated;
        }
    }
}
