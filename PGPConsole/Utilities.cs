using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PGPConsole
{
  internal static class Utilities
  {
    internal static byte[] Compress(string input, CompressionAlgorithmTag algorithmTag)
    {
      byte[] inputData = Encoding.Default.GetBytes(input);

      using (MemoryStream memoryStream = new MemoryStream())
      {
        PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(algorithmTag);

        using (Stream compressedStream = compressedDataGenerator.Open(memoryStream))
        using (Stream outputStream = new PgpLiteralDataGenerator().Open(compressedStream, PgpLiteralData.Binary, PgpLiteralData.Console, inputData.Length, DateTime.Now))
        {
          outputStream.Write(inputData, 0, inputData.Length);
        }
        compressedDataGenerator.Close();

        return memoryStream.ToArray();
      }
    }

    internal static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSecretKey, long keyId, char[] pass)
    {
      PgpSecretKey pgpSecKey = pgpSecretKey.GetSecretKey(keyId);

      return pgpSecKey?.ExtractPrivateKey(pass);
    }

    internal static PgpPublicKey ReadPublicKey(byte[] inputData)
    {
      using (Stream inputStream = PgpUtilities.GetDecoderStream(new MemoryStream(inputData)))
      {
        PgpPublicKeyRingBundle keyRingBundle = new PgpPublicKeyRingBundle(inputStream);

        foreach (PgpPublicKeyRing keyRing in keyRingBundle.GetKeyRings())
        {
          foreach (PgpPublicKey publicKey in keyRing.GetPublicKeys())
          {
            if (publicKey.IsEncryptionKey)
            {
              return publicKey;
            }
          }
        }
      }

      throw new ArgumentException("Can't find encryption key in key ring.");
    }

    internal static PgpSecretKey ReadSecretKey(Stream inputStream)
    {
      PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
        PgpUtilities.GetDecoderStream(inputStream));

      foreach (PgpSecretKeyRing keyRing in pgpSec.GetKeyRings())
      {
        foreach (PgpSecretKey key in keyRing.GetSecretKeys())
        {
          if (key.IsSigningKey)
          {
            return key;
          }
        }
      }

      throw new ArgumentException("Can't find signing key in key ring.");
    }
  }
}

