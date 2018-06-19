CryptionSlater: Generic CBC and HMAC Library for C#/.NET

by Logan Gore, github.com/logangore/cryptionSlater

================================================================

What is CryptionSlater?
CryptionSlater is a generic encryption and HMAC library that gives developers a simple and secure way to implement 
symmetric encryption and message authentication in .NET/C# 4+. CryptionSlater will help you avoid the errors commonly 
found in cryptographic solutions by providing a clean and intuitive interface. Even if you are new to C# or encryption, 
CryptionSlater will get you started quickly and with confidence. 

If You Are New To Encryption
CryptionSlater is easily implemented by the novice programmer, but designing a secure solution will involve much more 
than the examples and topics covered in this manual. It’s highly recommended that newcomers research both the theoretical 
and practical aspects of cryptography and secure development in your language and framework; in our case, this is .NET/C#.

CryptionSlater Features
Out-the-box, CryptionSlater offers generic implementation of the System.Security.Cryptography SymmetricAlgorithm and HMAC 
subclasses, random salts, chained PBKDF2 stretching, and will default to the strongest key and block sizes offered by the 
specified algorithm. Cipher and padding modes are set to CBC and PKCS7 (respectively) and cannot be adjusted. CryptionSlater 
also has custom features to make the developer’s life easier, like auto adjusting stretch iterations until a targeted 
timeframe has been met. 
