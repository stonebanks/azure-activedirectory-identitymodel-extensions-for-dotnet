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
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.References
{
    public class JsonWebTokenHandlerReferenceTests
    {
        [Theory, MemberData(nameof(RFC7515ReferenceTestCases))]
        public void RFC7515References(JwtReferenceTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.RFC7515References", theoryData);

            try
            {
                var jwt = JwtTokenUtilities.CreateCompactJWS(theoryData.Header, theoryData.Payload, theoryData.SigningCredentials);
                var jsonWebToken = new JsonWebToken(jwt);

                if (!theoryData.EncodedHeader.Equals(jsonWebToken.EncodedHeader, StringComparison.Ordinal))
                    context.AddDiff($"!theoryData.HeaderEncoded.Equals(jsonWebToken.EncodedHeader, StringComparison.Ordinal), theoryData.HeaderEncoded: '{theoryData.EncodedHeader}', jsonWebToken.EncodedHeader: '{jsonWebToken.EncodedHeader}'.");

                if (!theoryData.EncodedPayload.Equals(jsonWebToken.EncodedPayload, StringComparison.Ordinal))
                    context.AddDiff($"!theoryData.EncodedPayload.Equals(jsonWebToken.EncodedPayload, StringComparison.Ordinal), theoryData.EncodedPayload: '{theoryData.EncodedPayload}', jsonWebToken.EncodedPayload: '{jsonWebToken.EncodedPayload}'.");

                if (!theoryData.EncodedSignature.Equals(jsonWebToken.EncodedSignature, StringComparison.Ordinal))
                    context.AddDiff($"theoryData.EncodedSignature.Equals(jsonWebToken.EncodedSignature, StringComparison.Ordinal), theoryData.EncodedSignature: '{theoryData.EncodedSignature}', jsonWebToken.EncodedSignature: '{jsonWebToken.EncodedSignature}'.");

                if (!theoryData.EncodedToken.Equals(jsonWebToken.EncodedToken, StringComparison.Ordinal))
                    context.AddDiff($"!theoryData.EncodedToken.Equals(jsonWebToken.EncodedToken, StringComparison.Ordinal), theoryData.EncodedToken: '{theoryData.EncodedToken}', jsonWebToken.EncodedToken: '{jsonWebToken.EncodedToken}'.");

                if (!theoryData.EncodedToken.Equals(jwt, StringComparison.Ordinal))
                    context.AddDiff($"!theoryData.EncodedToken.Equals(jwt, StringComparison.Ordinal), theoryData.EncodedToken: '{theoryData.EncodedToken}', jwt: '{jwt}'.");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }


            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JwtReferenceTheoryData> RFC7515ReferenceTestCases
        {
            get => new TheoryData<JwtReferenceTheoryData>
            {
                new JwtReferenceTheoryData
                {
                    EncodedHeader = RFC7515.SymetricKeyHMACSHA2.EncodedHeader,
                    EncodedPayload = RFC7515.SymetricKeyHMACSHA2.EncodedPayload,
                    EncodedSignature = RFC7515.SymetricKeyHMACSHA2.EncodedSignature,
                    EncodedToken = RFC7515.SymetricKeyHMACSHA2.EncodedToken,
                    Header = RFC7515.SymetricKeyHMACSHA2.Header,
                    Payload = RFC7515.SymetricKeyHMACSHA2.Payload,
                    SigningCredentials = RFC7515.SymetricKeyHMACSHA2.SigningCredentials
                }
            };
        }
    }

    public class JwtReferenceTheoryData : TheoryDataBase
    {
        public string EncodedHeader { get; set; }

        public string EncodedPayload { get; set; }

        public string EncodedSignature { get; set; }

        public string EncodedToken { get; set; }

        public string Header { get; set; }

        public byte[] HeaderOctets { get; set; }

        public string Payload { get; set; }

        public byte[] PayloadOctets { get; set; }

        public byte[] SignatureOctets { get; set; }

        public SigningCredentials SigningCredentials { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
