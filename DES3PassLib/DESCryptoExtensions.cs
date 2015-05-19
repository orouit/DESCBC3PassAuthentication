/**
 * @author Olivier ROUIT
 * 
 * @license CPL, CodeProject license 
 */

using System;
using System.Reflection;
using System.Security.Cryptography;

namespace Core.Security
{
    public static class DESCryptoExtensions
    {
        public static ICryptoTransform CreateWeakEncryptor<T>(this T cryptoProvider, byte[] key, byte[] iv)
            where T : SymmetricAlgorithm
        {
            // reflective way of doing what CreateEncryptor() does, bypassing the check for weak keys
            MethodInfo mi = cryptoProvider.GetType().GetMethod("_NewEncryptor", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] Par = { key, cryptoProvider.Mode, iv, cryptoProvider.FeedbackSize, 0 };
            ICryptoTransform trans = mi.Invoke(cryptoProvider, Par) as ICryptoTransform;
            return trans;
        }

        public static ICryptoTransform CreateWeakEncryptor<T>(this T cryptoProvider)
            where T : SymmetricAlgorithm
        {
            return CreateWeakEncryptor(cryptoProvider, cryptoProvider.Key, cryptoProvider.IV);
        }

        public static ICryptoTransform CreateWeakDecryptor<T>(this T cryptoProvider, byte[] key, byte[] iv)
            where T : SymmetricAlgorithm
        {
            // reflective way of doing what CreateEncryptor() does, bypassing the check for weak keys
            MethodInfo mi = cryptoProvider.GetType().GetMethod("_NewEncryptor", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] Par = { key, cryptoProvider.Mode, iv, cryptoProvider.FeedbackSize, 1 };
            ICryptoTransform trans = mi.Invoke(cryptoProvider, Par) as ICryptoTransform;
            return trans;
        }

        public static ICryptoTransform CreateWeakDecryptor<T>(this TripleDESCryptoServiceProvider cryptoProvider)
            where T : SymmetricAlgorithm
        {
            return CreateWeakDecryptor(cryptoProvider, cryptoProvider.Key, cryptoProvider.IV);
        }

#if DES
        public static ICryptoTransform CreateWeakEncryptor(this DESCryptoServiceProvider cryptoProvider, byte[] key, byte[] iv)
        {
            // reflective way of doing what CreateEncryptor() does, bypassing the check for weak keys
            MethodInfo mi = cryptoProvider.GetType().GetMethod("_NewEncryptor", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] Par = { key, cryptoProvider.Mode, iv, cryptoProvider.FeedbackSize, 0 };
            ICryptoTransform trans = mi.Invoke(cryptoProvider, Par) as ICryptoTransform;
            return trans;
        }

        public static ICryptoTransform CreateWeakEncryptor(this DESCryptoServiceProvider cryptoProvider)
        {
            return CreateWeakEncryptor(cryptoProvider, cryptoProvider.Key, cryptoProvider.IV);
        }

        public static ICryptoTransform CreateWeakDecryptor(this DESCryptoServiceProvider cryptoProvider, byte[] key, byte[] iv)
        {
            // reflective way of doing what CreateEncryptor() does, bypassing the check for weak keys
            MethodInfo mi = cryptoProvider.GetType().GetMethod("_NewEncryptor", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] Par = { key, cryptoProvider.Mode, iv, cryptoProvider.FeedbackSize, 1 };
            ICryptoTransform trans = mi.Invoke(cryptoProvider, Par) as ICryptoTransform;
            return trans;
        }

        public static ICryptoTransform CreateWeakDecryptor(this DESCryptoServiceProvider cryptoProvider)
        {
            return CreateWeakDecryptor(cryptoProvider, cryptoProvider.Key, cryptoProvider.IV);
        }
#endif
    }
}
