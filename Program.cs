using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
/* Client Code to consume web service to encrypt and has message content. Client decrypts encrypted massage in the code.
 * Written by Kübra SARIOĞLU-YBU CENG 1105012001*/
namespace ClientToDecrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            ServiceReference1.Service1Client Client = new ServiceReference1.Service1Client();
            Console.WriteLine("Type message");
            string content= Console.ReadLine();
            
         String hashOfTheMessage=   Client.HashMessage(content);
            using (RijndaelManaged myRijndael = new RijndaelManaged())
            {
                byte[] encrypted = Client.EncryptStringToBytes(content, myRijndael.Key, myRijndael.IV);

                string roundtrip = DecryptStringFromBytes(encrypted, myRijndael.Key, myRijndael.IV);

                //Display the original data and the decrypted data.
                Console.WriteLine("Original Content:   {0}", content);
                Console.WriteLine("Hash of the message: {0}",hashOfTheMessage); //decrypt

                Console.WriteLine("Decrypted message:   {0}", roundtrip); //decrypt
                Console.Read();
            }
        }
        /*Client's decrypt methpd*/
         static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");

            // Declare the string used to hold 
            // the decrypted text.
            string plaintext = null;

            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream 
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }
      
    }
}