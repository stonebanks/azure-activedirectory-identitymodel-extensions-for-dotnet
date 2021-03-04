//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Defines the default set of algorithms this library supports
    /// </summary>
    internal static class SupportedAlgorithms
    {
        internal static readonly ICollection<string> EcdsaSigningAlgorithms = new Collection<string>
        {
            SecurityAlgorithms.EcdsaSha256,
            SecurityAlgorithms.EcdsaSha256Signature,
            SecurityAlgorithms.EcdsaSha384,
            SecurityAlgorithms.EcdsaSha384Signature,
            SecurityAlgorithms.EcdsaSha512,
            SecurityAlgorithms.EcdsaSha512Signature
        };

        internal static readonly ICollection<string> HashAlgorithms = new Collection<string>
        {
            SecurityAlgorithms.Sha256,
            SecurityAlgorithms.Sha256Digest,
            SecurityAlgorithms.Sha384,
            SecurityAlgorithms.Sha384Digest,
            SecurityAlgorithms.Sha512,
            SecurityAlgorithms.Sha512Digest
        };

        // doubles as RsaKeyWrapAlgorithms
        internal static readonly ICollection<string> RsaEncryptionAlgorithms = new Collection<string>
        {
            SecurityAlgorithms.RsaOAEP,
            SecurityAlgorithms.RsaPKCS1,
            SecurityAlgorithms.RsaOaepKeyWrap
        };

        internal static readonly ICollection<string> RsaSigningAlgorithms = new Collection<string>
        {
            SecurityAlgorithms.RsaSha256,
            SecurityAlgorithms.RsaSha256Signature,
            SecurityAlgorithms.RsaSha384,
            SecurityAlgorithms.RsaSha384Signature,
            SecurityAlgorithms.RsaSha512,
            SecurityAlgorithms.RsaSha512Signature
        };

        internal static readonly ICollection<string> RsaPssSigningAlgorithms = new Collection<string>
        {
            SecurityAlgorithms.RsaSsaPssSha256,
            SecurityAlgorithms.RsaSsaPssSha256Signature,
            SecurityAlgorithms.RsaSsaPssSha384,
            SecurityAlgorithms.RsaSsaPssSha384Signature,
            SecurityAlgorithms.RsaSsaPssSha512,
            SecurityAlgorithms.RsaSsaPssSha512Signature
        };

        internal static readonly ICollection<string> SymmetricEncryptionAlgorithms = new Collection<string>
        {
            SecurityAlgorithms.Aes128CbcHmacSha256,
            SecurityAlgorithms.Aes192CbcHmacSha384,
            SecurityAlgorithms.Aes256CbcHmacSha512,
            SecurityAlgorithms.Aes128Gcm,
            SecurityAlgorithms.Aes192Gcm,
            SecurityAlgorithms.Aes256Gcm
        };

        internal static readonly ICollection<string> SymmetricKeyWrapAlgorithms = new Collection<string>
        {
            SecurityAlgorithms.Aes128KW,
            SecurityAlgorithms.Aes128KeyWrap,
            SecurityAlgorithms.Aes256KW,
            SecurityAlgorithms.Aes256KeyWrap
        };

        internal static readonly ICollection<string> SymmetricSigningAlgorithms = new Collection<string>
        {
            SecurityAlgorithms.HmacSha256,
            SecurityAlgorithms.HmacSha256Signature,
            SecurityAlgorithms.HmacSha384,
            SecurityAlgorithms.HmacSha384Signature,
            SecurityAlgorithms.HmacSha512,
            SecurityAlgorithms.HmacSha512Signature
        };

#if NET461 || NET472 || NETSTANDARD2_0
        /// <summary>
        /// Creating a Signature requires the use of a <see cref="HashAlgorithm"/>.
        /// This method returns the <see cref="HashAlgorithmName"/>
        /// that describes the <see cref="HashAlgorithm"/>to use when generating a Signature.
        /// </summary>
        /// <param name="algorithm">The SignatureAlgorithm in use.</param>
        /// <returns>The <see cref="HashAlgorithmName"/> to use.</returns>
        /// <exception cref="ArgumentNullException">if <paramref name="algorithm"/> is null or whitespace.</exception>
        /// <exception cref="ArgumentOutOfRangeException">if <paramref name="algorithm"/> is not supported.</exception>
        internal static HashAlgorithmName GetHashAlgorithmName(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            switch (algorithm)
            {
                case SecurityAlgorithms.EcdsaSha256:
                case SecurityAlgorithms.EcdsaSha256Signature:
                case SecurityAlgorithms.RsaSha256:
                case SecurityAlgorithms.RsaSha256Signature:
                case SecurityAlgorithms.RsaSsaPssSha256:
                case SecurityAlgorithms.RsaSsaPssSha256Signature:
                    return HashAlgorithmName.SHA256;

                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.EcdsaSha384Signature:
                case SecurityAlgorithms.RsaSha384:
                case SecurityAlgorithms.RsaSha384Signature:
                case SecurityAlgorithms.RsaSsaPssSha384:
                case SecurityAlgorithms.RsaSsaPssSha384Signature:
                    return HashAlgorithmName.SHA384;

                case SecurityAlgorithms.EcdsaSha512:
                case SecurityAlgorithms.EcdsaSha512Signature:
                case SecurityAlgorithms.RsaSha512:
                case SecurityAlgorithms.RsaSha512Signature:
                case SecurityAlgorithms.RsaSsaPssSha512:
                case SecurityAlgorithms.RsaSsaPssSha512Signature:
                    return HashAlgorithmName.SHA512;
            }

            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(algorithm), LogHelper.FormatInvariant(LogMessages.IDX10652, algorithm)));
        }
#endif

        /// <summary>
        /// Creating a Signature requires the use of a <see cref="HashAlgorithm"/>.
        /// This method returns the HashAlgorithm string that is associated with a SignatureAlgorithm.
        /// </summary>
        /// <param name="algorithm">The SignatureAlgorithm of interest.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="algorithm"/>is null or whitespace.</exception>
        /// <exception cref="ArgumentException">if <paramref name="algorithm"/> is not supported.</exception>
        internal static string GetDigestFromSignatureAlgorithm(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            switch (algorithm)
            {
                case SecurityAlgorithms.EcdsaSha256:
                case SecurityAlgorithms.HmacSha256:
                case SecurityAlgorithms.RsaSha256:
                case SecurityAlgorithms.RsaSsaPssSha256:
                    return SecurityAlgorithms.Sha256;

                case SecurityAlgorithms.EcdsaSha256Signature:
                case SecurityAlgorithms.HmacSha256Signature:
                case SecurityAlgorithms.RsaSha256Signature:
                case SecurityAlgorithms.RsaSsaPssSha256Signature:
                    return SecurityAlgorithms.Sha256Digest;

                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.HmacSha384:
                case SecurityAlgorithms.RsaSha384:
                case SecurityAlgorithms.RsaSsaPssSha384:
                    return SecurityAlgorithms.Sha384;

                case SecurityAlgorithms.EcdsaSha384Signature:
                case SecurityAlgorithms.HmacSha384Signature:
                case SecurityAlgorithms.RsaSha384Signature:
                case SecurityAlgorithms.RsaSsaPssSha384Signature:
                    return SecurityAlgorithms.Sha384Digest;

                case SecurityAlgorithms.EcdsaSha512:
                case SecurityAlgorithms.HmacSha512:
                case SecurityAlgorithms.RsaSha512:
                case SecurityAlgorithms.RsaSsaPssSha512:
                    return SecurityAlgorithms.Sha512;

                case SecurityAlgorithms.EcdsaSha512Signature:
                case SecurityAlgorithms.HmacSha512Signature:
                case SecurityAlgorithms.RsaSha512Signature:
                case SecurityAlgorithms.RsaSsaPssSha512Signature:
                    return SecurityAlgorithms.Sha512Digest;
            }

            throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10652, algorithm), nameof(algorithm)));
        }

        /// <summary>
        /// Checks if an 'algorithm, key' pair is supported.
        /// </summary>
        /// <param name="algorithm">the algorithm to check.</param>
        /// <param name="key">the <see cref="SecurityKey"/>.</param>
        /// <returns>true if 'algorithm, key' pair is supported.</returns>
        public static bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        {
            if (key as RsaSecurityKey != null)
                return IsSupportedRsaAlgorithm(algorithm, key);

            if (key is X509SecurityKey x509Key)
            {
                // only RSA keys are supported
                if (x509Key.PublicKey as RSA == null)
                    return false;

                return IsSupportedRsaAlgorithm(algorithm, key);
            }

            if (key is JsonWebKey jsonWebKey)
            {
                if (JsonWebAlgorithmsKeyTypes.RSA.Equals(jsonWebKey.Kty, StringComparison.Ordinal))
                    return IsSupportedRsaAlgorithm(algorithm, key);
                else if (JsonWebAlgorithmsKeyTypes.EllipticCurve.Equals(jsonWebKey.Kty, StringComparison.Ordinal))
                    return IsSupportedEcdsaAlgorithm(algorithm);
                else if (JsonWebAlgorithmsKeyTypes.Octet.Equals(jsonWebKey.Kty, StringComparison.Ordinal))
                    return IsSupportedSymmetricAlgorithm(algorithm);

                return false;
            }

            if (key is ECDsaSecurityKey)
                return IsSupportedEcdsaAlgorithm(algorithm);

            if (key as SymmetricSecurityKey != null)
                return IsSupportedSymmetricAlgorithm(algorithm);

            return false;
        }

        internal static bool IsSupportedEncryptionAlgorithm(string algorithm, SecurityKey key)
        {
            if (key == null)
                return false;

            if (string.IsNullOrEmpty(algorithm))
                return false;

            if (!(IsAesCbc(algorithm) || IsAesGcm(algorithm)))
                return false;

            if (key is SymmetricSecurityKey)
                return true;

            if (key is JsonWebKey jsonWebKey)
                return (jsonWebKey.K != null && jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet);

            return false;
        }

        internal static bool IsAesGcm(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
                return false;

            return algorithm.Equals(SecurityAlgorithms.Aes128Gcm, StringComparison.Ordinal)
               || algorithm.Equals(SecurityAlgorithms.Aes192Gcm, StringComparison.Ordinal)
               || algorithm.Equals(SecurityAlgorithms.Aes256Gcm, StringComparison.Ordinal);
        }

        internal static bool IsAesCbc(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
                return false;

            return algorithm.Equals(SecurityAlgorithms.Aes128CbcHmacSha256, StringComparison.Ordinal)
               || algorithm.Equals(SecurityAlgorithms.Aes192CbcHmacSha384, StringComparison.Ordinal)
               || algorithm.Equals(SecurityAlgorithms.Aes256CbcHmacSha512, StringComparison.Ordinal);
        }

        internal static bool IsSupportedAesGcmEncryptionAlgorithm(string algorithm, SecurityKey key)
        {
            if (key == null)
                return false;

            if (string.IsNullOrEmpty(algorithm))
                return false;

            if (!(algorithm.Equals(SecurityAlgorithms.Aes128Gcm, StringComparison.Ordinal)
               || algorithm.Equals(SecurityAlgorithms.Aes192Gcm, StringComparison.Ordinal)
               || algorithm.Equals(SecurityAlgorithms.Aes256Gcm, StringComparison.Ordinal)))
                return false;

            if (key is SymmetricSecurityKey)
                return true;

            if (key is JsonWebKey jsonWebKey)
                return (jsonWebKey.K != null && jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet);

            return false;
        }

        private static bool IsSupportedEcdsaAlgorithm(string algorithm)
        {
            return EcdsaSigningAlgorithms.Contains(algorithm);
        }

        internal static bool IsSupportedHashAlgorithm(string algorithm)
        {
            return HashAlgorithms.Contains(algorithm);
        }

        internal static bool IsSupportedRsaKeyWrap(string algorithm, SecurityKey key)
        {
            if (key == null)
                return false;

            if (string.IsNullOrEmpty(algorithm))
                return false;

            if (!RsaEncryptionAlgorithms.Contains(algorithm))
                return false;

            if (key is RsaSecurityKey || key is X509SecurityKey || (key is JsonWebKey rsaJsonWebKey && rsaJsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA))
                return key.KeySize >= 2048;

            return false;
        }

        internal static bool IsSupportedSymmetricKeyWrap(string algorithm, SecurityKey key)
        {
            if (key == null)
                return false;

            if (string.IsNullOrEmpty(algorithm))
                return false;

            if (!SymmetricKeyWrapAlgorithms.Contains(algorithm))
                return false;

            return (key is SymmetricSecurityKey || (key is JsonWebKey jsonWebKey && jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet));
        }

        internal static bool IsSupportedRsaAlgorithm(string algorithm, SecurityKey key)
        {
            return RsaSigningAlgorithms.Contains(algorithm)
                || RsaEncryptionAlgorithms.Contains(algorithm)
                || (RsaPssSigningAlgorithms.Contains(algorithm) && IsSupportedRsaPss(key));
        }

        private static bool IsSupportedRsaPss(SecurityKey key)
        {
#if NET45
            // RSA-PSS is not available on .NET 4.5
            LogHelper.LogInformation(LogMessages.IDX10692);
            return false;
#elif NET461 || NET472 || NETSTANDARD2_0
            // RSACryptoServiceProvider doesn't support RSA-PSS
            if (key is RsaSecurityKey rsa && rsa.Rsa is RSACryptoServiceProvider)
            {
                LogHelper.LogInformation(LogMessages.IDX10693);
                return false;
            }
            else if (key is X509SecurityKey x509SecurityKey && x509SecurityKey.PublicKey is RSACryptoServiceProvider)
            {
                LogHelper.LogInformation(LogMessages.IDX10693);
                return false;
            }
            else
            {
                return true;
            }
#else
            return true;
#endif
        }

        internal static bool IsSupportedSymmetricAlgorithm(string algorithm)
        {
            return SymmetricEncryptionAlgorithms.Contains(algorithm)
                || SymmetricKeyWrapAlgorithms.Contains(algorithm)
                || SymmetricSigningAlgorithms.Contains(algorithm);
        }
    }
}
