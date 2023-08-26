// -*- coding: utf-8 -*-
using System;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Yekong.AuthME
{
    class TOTP
    {
        // public static void Main(string[] args)
        // {
        //     // Test the functions
        //     string key = GenerateKey();
        //     Console.WriteLine(key);
        //     string token = GenerateTOTPNow(key);
        //     Console.WriteLine(token);
        //     string keyPlus = GenerateKeyPlus();
        //     Console.WriteLine(keyPlus);
        //     string tokenPlus = GenerateTOTPPlusNow(keyPlus);
        //     Console.WriteLine(tokenPlus);
        // }

        public static string GenerateKey(int keyLong = 2048)
        {
            //chars = string.ascii_letters + string.digits + "+-"
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
            Random random = new Random();
            StringBuilder key = new StringBuilder();
            for (int i = 0; i < keyLong; i++)
            {
                key.Append(chars[random.Next(chars.Length)]);
            }
            return key.ToString();
        }

        public static string GenerateKeyPlus(int keyLong = 2048)
        {
            //chars = string.ascii_letters + string.digits + "+-"
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[keyLong];
            rng.GetBytes(bytes);
            StringBuilder key = new StringBuilder();
            for (int i = 0; i < keyLong; i++)
            {
                key.Append(chars[bytes[i] % chars.Length]);
            }
            return key.ToString();
        }

        public static string GenerateTOTP(string key, long timestamp, int window = 30000, int tokenLong = 128)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            long timestep = timestamp / window;
            HMac[] macs =
                {
                    new HMac(new Sha256Digest()),
                    new HMac(new Sha384Digest()),
                    new HMac(new Sha512Digest()),
                    new HMac(new MD5Digest()),
                    new HMac(new Sha1Digest()),
                    new HMac(new Sha224Digest())
                };
            
            byte[] macsBytes = new byte[0];
            
            foreach (HMac mac in macs)
            {
                mac.Init(new KeyParameter(keyBytes));
                mac.BlockUpdate(BitConverter.GetBytes(timestep), 0, 8);
                byte[] output1 = new byte[mac.GetUnderlyingDigest().GetDigestSize()];
                mac.DoFinal(output1, 0);

                mac.Init(new KeyParameter(keyBytes));
                mac.BlockUpdate(BitConverter.GetBytes(timestep).Reverse().ToArray(), 0, 8);
                byte[] output2 = new byte[mac.GetUnderlyingDigest().GetDigestSize()];
                mac.DoFinal(output2, 0);

                macsBytes = macsBytes.Concat(output1).Concat(output2).ToArray();
                
            }
            
            string encodedMacs = Convert.ToBase64String(macsBytes).TrimEnd('=');
            
            int offset = 0;
            
            string token = encodedMacs.Substring(offset, tokenLong);
            
            token = token.Replace("/", "-");
            
            token = token.Replace("=", "+");
            
            return token;
        }

        public static string GenerateTOTPPlus(string key, long timestamp, int window = 30000, int tokenLong = 128)
        {
            
             byte[] keyBytes = Encoding.UTF8.GetBytes(key);
             long timestep = timestamp / window;
             HMac[] macs =
                 {
                     new HMac(new Sha256Digest()),
                     new HMac(new Sha384Digest()),
                     new HMac(new Sha512Digest()),
                     new HMac(new MD5Digest()),
                     new HMac(new Sha1Digest()),
                     new HMac(new Sha224Digest()),
                     new HMac(new Sha3Digest(256)),
                     new HMac(new Sha3Digest(384)),
                     new HMac(new Sha3Digest(512)),
                     new HMac(new Sha3Digest(224))
                 };
             
             byte[] macsBytes = new byte[0];
             
             foreach (HMac mac in macs)
             {
                 mac.Init(new KeyParameter(keyBytes));
                 mac.BlockUpdate(BitConverter.GetBytes(timestep), 0, 8);
                 byte[] output1a = new byte[mac.GetUnderlyingDigest().GetDigestSize()];
                 mac.DoFinal(output1a, 0);

                 mac.Init(new KeyParameter(output1a));
                 mac.BlockUpdate(BitConverter.GetBytes(timestep).Reverse().ToArray(), 0, 8);
                 byte[] output1b = new byte[mac.GetUnderlyingDigest().GetDigestSize()];
                 mac.DoFinal(output1b, 0);

                 macsBytes = macsBytes.Concat(output1b).ToArray();

                 mac.Init(new KeyParameter(keyBytes));
                 mac.BlockUpdate(BitConverter.GetBytes(timestep), 0, 8);
                 byte[] output2a = new byte[mac.GetUnderlyingDigest().GetDigestSize()];
                 mac.DoFinal(output2a, 0);

                 macsBytes = macsBytes.Concat(output2a).ToArray();

                 mac.Init(new KeyParameter(keyBytes));
                 mac.BlockUpdate(BitConverter.GetBytes(timestep).Reverse().ToArray(), 0, 8);
                 byte[] output3a = new byte[mac.GetUnderlyingDigest().GetDigestSize()];
                 mac.DoFinal(output3a, 0);

                 mac.Init(new KeyParameter(output3a));
                 mac.BlockUpdate(BitConverter.GetBytes(timestep), 0, 8);
                 byte[] output3b = new byte[mac.GetUnderlyingDigest().GetDigestSize()];
                 mac.DoFinal(output3b, 0);

                 macsBytes = macsBytes.Concat(output3b).ToArray();

                 mac.Init(new KeyParameter(keyBytes));
                 mac.BlockUpdate(BitConverter.GetBytes(timestep).Reverse().ToArray(), 0, 8);
                 byte[] output4a = new byte[mac.GetUnderlyingDigest().GetDigestSize()];
                 mac.DoFinal(output4a, 0);

                 macsBytes = macsBytes.Concat(output4a).ToArray();
                 
             }
             
             string encodedMacs = Convert.ToBase64String(macsBytes).TrimEnd('=');
             
             int offset = 0;
             
             string token = encodedMacs.Substring(offset, tokenLong);
             
             token = token.Replace("/", "-");
             
             token = token.Replace("=", "+");
             
             return token;
        }

        public static string GenerateTOTPNow(string key, int window = 30000, int tokenLong = 128)
        {
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            return GenerateTOTP(key, timestamp, window, tokenLong);
        }

        public static string GenerateTOTPPlusNow(string key, int window = 30000, int tokenLong = 128)
        {
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            return GenerateTOTPPlus(key, timestamp, window, tokenLong);
        }
    }
}
