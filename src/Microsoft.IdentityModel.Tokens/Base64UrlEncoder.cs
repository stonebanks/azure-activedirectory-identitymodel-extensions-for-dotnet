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
using System.Text;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Encodes and Decodes strings using Base64Url encoding.
    /// see: https://tools.ietf.org/html/rfc4648#page-7
    /// base64url encoding extends and is slightly different from base64 encoding:
    /// * padding is skipped so the pad character '=' doesn't have to be percent encoded
    /// * the 62nd and 63rd regular base64 encoding characters ('+' and '/') are replace with ('-' and '_')
    /// These changes make work better with http messages and are considered URL safe.
    /// </summary>
    public static class Base64UrlEncoder
    {
        private static char base64PadCharacter = '=';
        private static string doubleBase64PadCharacter = "==";
        private static char base64Character62 = '+';
        private static char base64Character63 = '/';
        private static char base64UrlCharacter62 = '-';
        private static char _base64UrlCharacter63 = '_';

        /// <summary>
        /// Encodes a string using Base64Url encoding.
        /// </summary>
        /// <param name="arg">string to encode.</param>
        /// <returns>Base64Url encoded string</returns>
        /// <remarks>Assumes UTF8 encoding of string.</remarks>
        /// <exception cref="ArgumentNullException"><paramref name="arg"/> is null.</exception>
        public static string Encode(string arg)
        {
            if (arg == null)
                throw LogHelper.LogArgumentNullException(nameof(arg));

            return Encode(Encoding.UTF8.GetBytes(arg));
        }

        /// <summary>
        /// Converts a subset of a byte array to a Base64Url encoded string.digits.
        /// </summary>
        /// <param name="inArray">Bytes to encode.</param>
        /// <param name="length">Offset in inArray.</param>
        /// <param name="offset">The number of elements of inArray to convert.</param>
        /// <returns>A string encoded as Base64Url starting from <paramref name="offset"/> of length <paramref name="length"/>.</returns>
        /// <exception cref="ArgumentNullException">'inArray' is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">offset or length is negative.</exception>
        /// <exception cref="ArgumentOutOfRangeException">offset plus length is greater than the length of inArray.</exception>
        public static string Encode(byte[] inArray, int offset, int length)
        {
            if (inArray == null)
                throw LogHelper.LogArgumentNullException(nameof(inArray));

            if (offset < 0)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10402, offset)));

            if (length < 0)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10403, length)));

            if (offset + length > inArray.Length)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10404, offset, length, inArray.Length)));

            string s = Convert.ToBase64String(inArray, offset, length);
            s = s.Split(base64PadCharacter)[0]; // Remove any trailing padding
            s = s.Replace(base64Character62, base64UrlCharacter62);  // 62nd char of encoding
            s = s.Replace(base64Character63, _base64UrlCharacter63);  // 63rd char of encoding
            return s;
        }

        /// <summary>
        /// Converts a byte array to a Base64Url encoded string.
        /// </summary>
        /// <param name="inArray">bytes to encode.</param>
        /// <returns>A string encoded as Base64Url.</returns>
        /// <exception cref="ArgumentNullException">'inArray' is null.</exception>
        public static string Encode(byte[] inArray)
        {
            if (inArray == null)
                throw LogHelper.LogArgumentNullException(nameof(inArray));

            string s = Convert.ToBase64String(inArray, 0, inArray.Length);
            s = s.Split(base64PadCharacter)[0]; // Remove any trailing padding
            s = s.Replace(base64Character62, base64UrlCharacter62);  // 62nd char of encoding
            s = s.Replace(base64Character63, _base64UrlCharacter63);  // 63rd char of encoding

            return s;
        }

        /// <summary>
        /// Decodes the specified string, encoded using Base64Url to bytes.
        /// </summary>
        /// <param name="str">Base64Url encoded string.</param>
        /// <returns>Original bytes used to create the string.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="str"/> is null.</exception>
        /// <exception cref="FormatException">if str.length mod 4 == 1, which indicates invalid string size as padding is implied..</exception>
        public static byte[] DecodeBytes(string str)
        {
            if (str == null)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(str)));
            }

            // 62nd char of encoding
            str = str.Replace(base64UrlCharacter62, base64Character62);

            // 63rd char of encoding
            str = str.Replace(_base64UrlCharacter63, base64Character63);

            // check for padding
            switch (str.Length % 4)
            {
                case 0:
                    // No pad chars in this case
                    break;
                case 2:
                    // Two pad chars
                    str += doubleBase64PadCharacter;
                    break;
                case 3:
                    // One pad char
                    str += base64PadCharacter;
                    break;
                default:
                    throw LogHelper.LogExceptionMessage(new FormatException(LogHelper.FormatInvariant(LogMessages.IDX10400, str)));
            }

            return Convert.FromBase64String(str);
        }

        /// <summary>
        ///  Converts the specified base64Url encoded string to the base64 string including padding.</summary>
        /// <param name="str">base64-url-encoded string.</param>
        /// <returns>base64 string.</returns>
        internal static string GetBase64String(string str)
        {
            // 62nd char of encoding
            var base64Str = str.Replace(base64UrlCharacter62, base64Character62);

            // 63rd char of encoding
            base64Str = base64Str.Replace(_base64UrlCharacter63, base64Character63);

            // check for padding
            switch (str.Length % 4)
            {
                case 0:
                    // No pad chars in this case
                    break;

                case 2:
                    // Two pad chars
                    base64Str += doubleBase64PadCharacter;
                    break;

                case 3:
                    // One pad char
                    base64Str += base64PadCharacter;
                    break;

                default:
                    throw LogHelper.LogExceptionMessage(new FormatException(LogHelper.FormatInvariant(LogMessages.IDX10400, str)));
            }

            return base64Str;
        }

        /// <summary>
        /// Decodes the string from Base64UrlEncoded to UTF8.
        /// </summary>
        /// <param name="arg">string to decode.</param>
        /// <returns>UTF8 string.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="arg"/> is null.</exception>
        public static string Decode(string arg)
        {
            return Encoding.UTF8.GetString(DecodeBytes(arg));
        }
    }
}
