/**
 * @author Olivier ROUIT
 * 
 * @license CPL, CodeProject license 
 */

namespace Core.Security
{
    interface IPCDAuthentication
    {
        /// <summary>
        /// Executes the step2 of a triple pass authentication (PICC connected to a PCD)
        /// </summary>
        /// <param name="encRndB">RndB' encyphered with keyNo from authentication step 1</param>
        /// <returns>RndA + RndB' decyphered with the same key as keyNo</returns>
        byte[] AuthenticateStep2(byte[] encRndB);

        /// <summary>
        /// Executes the step 3 of a triple pass authentication (PICC connected to a PCD)
        /// </summary>
        /// <param name="encRndAr">RndA' encyphered with keyNo from authentication step 2</param>
        /// <returns>true if the PICC has been authenticated by the PCD, false otehrwise</returns>
        bool AuthenticateStep4(byte[] encRndAr);
    }
}
