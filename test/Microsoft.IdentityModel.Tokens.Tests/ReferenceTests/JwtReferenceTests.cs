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
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.References
{
    public class JwtReferenceTests
    {
        [Theory, MemberData(nameof(JwtHeaderEncodingTestCases))]
        public void JwtHeaderEncoding(JwtReferenceTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.JwtHeaderEncoding", theoryData);

            try
            {
                var encodedData = theoryData.JwtHeader.Base64UrlEncode();
                if (!string.Equals(theoryData.EncodedData, theoryData.JwtHeader.Base64UrlEncode(), StringComparison.Ordinal))
                    context.AddDiff($"(!string.Equals(theoryData.EncodedData: '{theoryData.EncodedData}', theoryData.JwtHeader.Base64UrlEncode(): '{encodedData}', StringComparison.Ordinal))");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }


            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JwtReferenceTheoryData> JwtHeaderEncodingTestCases
        {
            get => new TheoryData<JwtReferenceTheoryData>
            {
                new JwtReferenceTheoryData
                {
                    JwtHeader = RFC7520References.ES512JwtHeader,
                    EncodedData = RFC7520References.ES512HeaderEncoded,
                    TestId = "RFC7520References_ES512HeaderEncoded"
                },
                new JwtReferenceTheoryData
                {
                    JwtHeader = RFC7520References.RSAJwtHeader,
                    EncodedData = RFC7520References.RSAHeaderEncoded,
                    TestId = "RFC7520References_RSAJwtHeader"
                },
                new JwtReferenceTheoryData
                {
                    JwtHeader = RFC7520References.SymmetricJwtHeader,
                    EncodedData = RFC7520References.SymmetricHeaderEncoded,
                    TestId = "RFC7520References_SymmetricJwtHeader"
                }
            };
        }

        [Theory, MemberData(nameof(JwtSigningTestCases))]
        public void JwtSigning(JwtReferenceTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.JwtHeaderEncoding", theoryData);

            try
            {
                var providerForSigning = CryptoProviderFactory.Default.CreateForSigning(theoryData.PrivateKey, theoryData.Algorithm);
                var providerForVerifying = CryptoProviderFactory.Default.CreateForVerifying(theoryData.PublicKey, theoryData.Algorithm);
                var signatureBytes = providerForSigning.Sign(Encoding.UTF8.GetBytes(theoryData.EncodedData));
                var encodedSignature = Base64UrlEncoder.Encode(signatureBytes);

                // Signatures aren't necessarily deterministic across different algorithms
                if (theoryData.DeterministicSignatures)
                {
                    if (!theoryData.EncodedSignature.Equals(encodedSignature, StringComparison.Ordinal))
                        context.AddDiff($"if (!theoryData.EncodedSignature.Equals(encodedSignature, StringComparison.Ordinal)).");
                }

                if (!providerForVerifying.Verify(Encoding.UTF8.GetBytes(theoryData.EncodedData), Base64UrlEncoder.DecodeBytes(theoryData.EncodedSignature)))
                    context.AddDiff($"providerForVerifying.Verify Failed: Algorithm: '{theoryData.Algorithm}'.");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch(Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JwtReferenceTheoryData> JwtSigningTestCases
        {
            get => new TheoryData<JwtReferenceTheoryData>
            {

                new JwtReferenceTheoryData
                {
                    Algorithm = RFC7520References.RSAJwtHeader.Alg,
                    EncodedData = RFC7520References.RSAEncoded,
                    EncodedSignature = RFC7520References.RSASignatureEncoded,
                    DeterministicSignatures = true,
                    PrivateKey = RFC7520References.RSASigningPrivateKey,
                    PublicKey = RFC7520References.RSASigningPublicKey,
                    TestId = "RFC7520References_RSAEncoded"
                },
                new JwtReferenceTheoryData
                {
                    Algorithm = RFC7520References.ES512JwtHeader.Alg,
                    EncodedData = RFC7520References.ES512Encoded,
                    EncodedSignature = RFC7520References.ES512SignatureEncoded,
                    DeterministicSignatures = false,
                    PrivateKey = RFC7520References.ECDsaPrivateKey,
                    PublicKey = RFC7520References.ECDsaPublicKey,
                    TestId = "RFC7520References_ES512Encoded"
                },
                new JwtReferenceTheoryData
                {
                    Algorithm = RFC7520References.SymmetricJwtHeader.Alg,
                    EncodedData = RFC7520References.SymmetricEncoded,
                    EncodedSignature = RFC7520References.SymmetricSignatureEncoded,
                    DeterministicSignatures = true,
                    PrivateKey = RFC7520References.SymmetricKeyMac,
                    PublicKey = RFC7520References.SymmetricKeyMac,
                    TestId = "RFC7520References_SymmetricEncoded"
                }
            };
        }

        public class JwtReferenceTheoryData : TheoryDataBase
        {
            public string Algorithm { get; set; }

            public string Data { get; set; }

            public string EncodedData { get; set; }

            public string EncodedSignature { get; set; }

            public bool DeterministicSignatures { get; set; }

            public JwtHeader JwtHeader { get; set; }

            public SecurityKey PrivateKey { get; set; }

            public SecurityKey PublicKey { get; set; }
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
