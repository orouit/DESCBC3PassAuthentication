/**
 * @author Olivier ROUIT
 * 
 * @license CPL, CodeProject license 
 */

namespace Core.Security
{
    interface IPICCAuthentication
    {
        /// <summary>
        /// Executes the step 1 of a triple pass authentication with a PICC (DESFire)
        /// </summary>
        /// <param name="keyNo">Key number, default is o => Master Key</param>
        /// <returns>ENC(RndB), 8 bytes RndB encyphered with KeyNo</returns>
        byte[] AuthenticateStep1(int keyNo = 0);

        /// <summary>
        /// Rexecutes the step 3 of a triple pass authentication with a PICC (DESFire)
        /// </summary>
        /// <param name="decRndABr">RndA + RndB' decyphered with the same key as keyNo</param>
        /// <param name="encRndAr">[out] If authentication successful, RndA' encyphered with keyNo</param>
        /// <returns>true if PCD has been authenticated, false otherwise</returns>
        bool AuthenticateStep3(byte[] decRndABr, out byte[] encRndAr);
    }
}
