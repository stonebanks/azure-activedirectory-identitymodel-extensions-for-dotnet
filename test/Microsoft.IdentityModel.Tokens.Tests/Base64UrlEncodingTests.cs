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

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class Base64UrlEncodingTests
    {
        [Theory, MemberData(nameof(EncodeTestCases))]
        public void Base64UrlEncoding(Base64UrlEncodingTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.Base64UrlEncoding", theoryData);

            try
            {
                var decodedData = Base64UrlEncoder.Encode(theoryData.Data);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch( Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Base64UrlEncodingTheoryData> EncodeTestCases
        {
            get => new TheoryData<Base64UrlEncodingTheoryData> 
            {
                new Base64UrlEncodingTheoryData
                {
                    Data = null,
                    ExpectedException = ExpectedException.ArgumentNullException("arg"),
                    TestId = "arg_null"
                },
            };
        }

        public class Base64UrlEncodingTheoryData : TheoryDataBase
        {
            public string Data { get; set; }

            public string EncodedData { get; set; }

            public int Length { get; set; }

            public int OffSet { get; set; }

        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
