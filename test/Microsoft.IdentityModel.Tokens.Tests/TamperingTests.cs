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
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

using ALG = Microsoft.IdentityModel.Tokens.SecurityAlgorithms;
using KEY = Microsoft.IdentityModel.TestUtils.KeyingMaterial;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// This class tests tampering of tokens
    /// </summary>
    public class TamperingTests
    {
#if NET_CORE
        // Excluding OSX as SignatureTampering test is slow on OSX (~6 minutes)
        // especially tests with IDs RS256 and ES256
        [PlatformSpecific(TestPlatforms.Windows | TestPlatforms.Linux)]
#endif
        /// <summary>
        /// Flips signature bit by bit
        /// </summary>
        /// <param name="theoryData"></param>
        [Theory, MemberData(nameof(SignatureTamperingTestCases))]
        [Trait("Signature", "Tampering")]
        public void SignatureTampering(SignatureProviderTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignatureTampering", theoryData);
            var copiedSignature = theoryData.Signature.CloneByteArray();
            for (int i = 0; i < theoryData.Signature.Length; i++)
            {
                var originalB = theoryData.Signature[i];
                for (byte b = 0; b < byte.MaxValue; b++)
                {
                    // skip here as this will succeed
                    if (b == theoryData.Signature[i])
                        continue;

                    copiedSignature[i] = b;
                    Assert.False(theoryData.VerifySignatureProvider.Verify(theoryData.RawBytes, copiedSignature), $"signature should not have verified: {theoryData.TestId} : {i} : {b} : {copiedSignature[i]}");

                    // reset so we move to next byte
                    copiedSignature[i] = originalB;
                }
            }

            Assert.True(theoryData.VerifySignatureProvider.Verify(theoryData.RawBytes, copiedSignature), "Final check should have verified");
        }

#if NET_CORE
        // Excluding OSX as SignatureTruncation test throws an exception only on OSX
        // This behavior should be fixed with netcore3.0
        // Exceptions is thrown somewhere in System/Security/Cryptography/DerEncoder.cs class which is removed in netcore3.0
        [PlatformSpecific(TestPlatforms.Windows | TestPlatforms.Linux)]
#endif
        /// <summary>
        /// Removes bytes one by one
        /// </summary>
        /// <param name="theoryData"></param>
        [Theory, MemberData(nameof(SignatureTamperingTestCases))]
        [Trait("Signature", "Truncation")]
        public void SignatureTruncation(SignatureProviderTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignatureTruncation", theoryData);
            for (int i = 0; i < theoryData.Signature.Length - 1; i++)
            {
                var truncatedSignature = new byte[i + 1];
                Array.Copy(theoryData.Signature, truncatedSignature, i + 1);
                Assert.False(theoryData.VerifySignatureProvider.Verify(theoryData.RawBytes, truncatedSignature), $"signature should not have verified: {theoryData.TestId} : {i}");
            }

            Assert.True(theoryData.VerifySignatureProvider.Verify(theoryData.RawBytes, theoryData.Signature), "Final check should have verified");
        }

        public static TheoryData<SignatureProviderTheoryData> SignatureTamperingTestCases()
        {
            var theoryData = new TheoryData<SignatureProviderTheoryData>();

            var rawBytes = Guid.NewGuid().ToByteArray();
            var asymmetricProvider = new AsymmetricSignatureProvider(KEY.DefaultX509Key_2048, ALG.RsaSha256, true);
            theoryData.Add(new SignatureProviderTheoryData
            {
                First = true,
                RawBytes = rawBytes,
                Signature = asymmetricProvider.Sign(rawBytes),
                TestId = ALG.RsaSha256,
                VerifyKey = KEY.DefaultX509Key_2048,
                VerifyAlgorithm = ALG.RsaSha256,
                VerifySignatureProvider = asymmetricProvider
            });

            var asymmetricProvider2 = new AsymmetricSignatureProvider(KEY.Ecdsa256Key, ALG.EcdsaSha256, true);
            theoryData.Add(new SignatureProviderTheoryData
            {
                RawBytes = rawBytes,
                Signature = asymmetricProvider2.Sign(rawBytes),
                TestId = ALG.EcdsaSha256,
                VerifyKey = KEY.Ecdsa256Key,
                VerifyAlgorithm = ALG.EcdsaSha256,
                VerifySignatureProvider = asymmetricProvider2
            });

            var symmetricProvider = new SymmetricSignatureProvider(KEY.SymmetricSecurityKey2_256, ALG.HmacSha256);
            theoryData.Add(new SignatureProviderTheoryData
            {
                RawBytes = rawBytes,
                Signature = symmetricProvider.Sign(rawBytes),
                TestId = ALG.HmacSha256,
                VerifyKey = KEY.SymmetricSecurityKey2_256,
                VerifyAlgorithm = ALG.HmacSha256,
                VerifySignatureProvider = symmetricProvider,
            });

            var symmetricProvider2 = new SymmetricSignatureProvider(KEY.SymmetricSecurityKey2_512, ALG.HmacSha512);
            theoryData.Add(new SignatureProviderTheoryData
            {
                RawBytes = rawBytes,
                Signature = symmetricProvider2.Sign(rawBytes),
                TestId = ALG.HmacSha512,
                VerifyKey = KEY.SymmetricSecurityKey2_512,
                VerifyAlgorithm = ALG.HmacSha512,
                VerifySignatureProvider = symmetricProvider2
            });

            return theoryData;
        }

        /// <summary>
        /// Validates that modifying the last byte of a Base64Url encoded signature is OK as it is a result of how padding works.
        /// </summary>
        /// <param name="theoryData"></param>
        [Theory, MemberData(nameof(JWSTamperingTestCases))]
        [Trait("JWS", "Tampering")]
        public void JWSTampering(JWSTamperingTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.JWSTampering", theoryData);
            var jsonTokenHandler = new JsonWebTokenHandler();
            var base64Signature = Base64UrlEncoder.GetBase64String(theoryData.EncodedSignature);
            try
            {
                var jsonWebToken = jsonTokenHandler.ValidateSignature(theoryData.Json, theoryData.TokenValidationParameters);

                // check padding before ProcessNoException
                // if there is padding, ensure that base64 bytes are the same and ensure tokens are equal
                if (base64Signature.EndsWith("="))
                {
                    var base64SignatureBytes = Convert.FromBase64String(base64Signature);
                    var base64ModifiedSignatureBytes = Convert.FromBase64String(Base64UrlEncoder.GetBase64String(theoryData.EncodedModifiedSignature));

                    IdentityComparer.AreBytesEqual(base64SignatureBytes, base64ModifiedSignatureBytes, context);
                    context.PropertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>>
                    {
                        { typeof(JsonWebToken), new List<string> { "EncodedToken", "EncodedSignature", "SigningKey" } },
                    };

                    IdentityComparer.AreEqual(jsonWebToken, theoryData.JsonWebToken, context);
                }
                else
                    theoryData.ExpectedException.ProcessNoException(context);
            }
            catch(Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JWSTamperingTheoryData> JWSTamperingTestCases()
        {

            var theoryData = new TheoryData<JWSTamperingTheoryData>();

            AddTestCases(SecurityAlgorithms.RsaSha512, KeyingMaterial.RsaSecurityKey_4096, theoryData, "RsaSecurityKey_4096_");
            AddTestCases(SecurityAlgorithms.RsaSha256, KeyingMaterial.RsaSecurityKey_2048, theoryData, "RsaSecurityKey_2048_");
            AddTestCases(SecurityAlgorithms.EcdsaSha256, KeyingMaterial.Ecdsa256Key, theoryData, "Ecdsa256Key_");
            AddTestCases(SecurityAlgorithms.EcdsaSha384, KeyingMaterial.Ecdsa384Key, theoryData, "Ecdsa384Key_");
            AddTestCases(SecurityAlgorithms.EcdsaSha512, KeyingMaterial.Ecdsa521Key, theoryData, "Ecdsa521Key_");
            AddTestCases(SecurityAlgorithms.HmacSha256, KeyingMaterial.DefaultSymmetricSecurityKey_128, theoryData, "DefaultSymmetricSecurityKey_128_");
            AddTestCases(SecurityAlgorithms.HmacSha384, KeyingMaterial.DefaultSymmetricSecurityKey_256, theoryData, "DefaultSymmetricSecurityKey_128_");
            AddTestCases(SecurityAlgorithms.HmacSha512, KeyingMaterial.DefaultSymmetricSecurityKey_512, theoryData, "DefaultSymmetricSecurityKey_128_");

            return theoryData;
        }

        private static void AddTestCases(string securityAlgorithm, SecurityKey securityKey, TheoryData<JWSTamperingTheoryData> theoryData, string testId)
        {
            var alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

            var tokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = securityKey,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false
            };

            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = Default.Audience,
                Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                Issuer = Default.Issuer,
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow,
                SigningCredentials = new SigningCredentials(securityKey, securityAlgorithm),
                Subject = Default.ClaimsIdentity,
            };

            var jwt = (new JsonWebTokenHandler()).CreateToken(securityTokenDescriptor);
            foreach (var ch in alphabet)
            {
                var jsonToken = new JsonWebToken(jwt);
                if (ch != jsonToken.EncodedSignature[jsonToken.EncodedSignature.Length - 1])
                {
                    var header = jsonToken.EncodedHeader;
                    var payload = jsonToken.EncodedPayload;
                    var modifiedSignature = jsonToken.EncodedSignature.Substring(0, jsonToken.EncodedSignature.Length - 1) + ch;
                    var modifiedJwt = header + "." + payload + "." + modifiedSignature;
                    theoryData.Add(new JWSTamperingTheoryData
                    {
                        EncodedModifiedSignature = modifiedSignature,
                        EncodedSignature = jsonToken.EncodedSignature,
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException(),
                        JsonWebToken = jsonToken,
                        Json = modifiedJwt,
                        TestId = testId + ch,
                        TokenValidationParameters = tokenValidationParameters
                    });
                }
            }
        }
    }

    public class JWSTamperingTheoryData : TheoryDataBase
    {
        public string Json { get; set; }

        public JsonWebToken JsonWebToken { get; set; }

        public string EncodedSignature { get; set; }

        public string EncodedModifiedSignature { get; set; }

        public TokenValidationParameters TokenValidationParameters { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
