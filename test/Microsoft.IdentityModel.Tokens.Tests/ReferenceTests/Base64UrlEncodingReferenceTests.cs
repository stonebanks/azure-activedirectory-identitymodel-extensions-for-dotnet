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
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.References
{
    public class Base64UrlEncodingReferenceTests
    {
        [Theory, MemberData(nameof(Base64UrlEncodingTestCases))]
        public void Base64UrlEncoding(Base64UrlEncodingReferenceTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.Base64UrlEncoding", theoryData);

            try
            {
                var decodedData = Base64UrlEncoder.Decode(theoryData.EncodedData);
                if (!theoryData.Data.Equals(decodedData, StringComparison.Ordinal))
                    context.Diffs.Add($"!theoryData.Data.Equals(decodecData, StringComparison.Ordinal), theoryData.EncodedData, decodedData:{Environment.NewLine}'{theoryData.Data}'{Environment.NewLine}'{decodedData}'");

                var encodedData = Base64UrlEncoder.Encode(theoryData.Data);
                if (!theoryData.EncodedData.Equals(encodedData, StringComparison.Ordinal))
                    context.Diffs.Add($"!theoryData.EncodedData.Equals(encodedData, StringComparison.Ordinal), theoryData.EncodedData, encodedData:{Environment.NewLine}'{theoryData.EncodedData}'{Environment.NewLine}'{encodedData}'");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch( Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Base64UrlEncodingReferenceTheoryData> Base64UrlEncodingTestCases
        {
            get => new TheoryData<Base64UrlEncodingReferenceTheoryData> 
            {
                new Base64UrlEncodingReferenceTheoryData
                {
                    Data = RFC7520References.Payload,
                    EncodedData = RFC7520References.PayloadEncoded,
                    TestId = "RFC7520References_Payload"
                },
                new Base64UrlEncodingReferenceTheoryData
                {
                    Data = RFC7520References.RSAHeaderJson,
                    EncodedData = RFC7520References.RSAHeaderEncoded,
                    TestId = "RFC7520References_RSAHeaderJson"
                },
                new Base64UrlEncodingReferenceTheoryData
                {
                    Data = RFC7520References.ES512HeaderJson,
                    EncodedData = RFC7520References.ES512HeaderEncoded,
                    TestId = "RFC7520References_ES512HeaderJson"
                },
                new Base64UrlEncodingReferenceTheoryData
                {
                    Data = RFC7520References.SymmetricHeaderJson,
                    EncodedData = RFC7520References.SymmetricHeaderEncoded,
                    TestId = "RFC7520References_SymmetricHeaderJson"
                },
                new Base64UrlEncodingReferenceTheoryData
                {
                    Data = RFC7515.SymetricKeyHMACSHA2.Header,
                    EncodedData = RFC7515.SymetricKeyHMACSHA2.EncodedHeader,
                    TestId = "RFC7515_SymetricKeyHMACSHA2_Header"
                },
                new Base64UrlEncodingReferenceTheoryData
                {
                    Data = RFC7515.SymetricKeyHMACSHA2.Payload,
                    EncodedData = RFC7515.SymetricKeyHMACSHA2.EncodedPayload,
                    TestId = "RFC7515_SymetricKeyHMACSHA2_Payload"
                },
            };
        }

        public class Base64UrlEncodingReferenceTheoryData : TheoryDataBase
        {
            public string Data { get; set; }

            public string EncodedData { get; set; }
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
