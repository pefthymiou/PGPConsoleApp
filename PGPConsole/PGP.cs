using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PGPConsole
{
  public static class PGP
  {
    public static string EncryptData(string input, byte[] publicKey)
    {
      byte[] compressedData = Utilities.Compress(input, CompressionAlgorithmTag.Zip);
      PgpPublicKey pgpPublicKey = Utilities.ReadPublicKey(publicKey);

      using (MemoryStream memoryStream = new MemoryStream())
      {
        using (Stream outputStream = new ArmoredOutputStream(memoryStream))
        {
          PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, true, new SecureRandom());
          encryptedDataGenerator.AddMethod(pgpPublicKey);

          using (Stream encryptedStream = encryptedDataGenerator.Open(outputStream, compressedData.Length))
          {
            encryptedStream.Write(compressedData, 0, compressedData.Length);
          }
        }

        return Encoding.Default.GetString(memoryStream.ToArray(), 0, memoryStream.ToArray().Length);
      }
    }

    public static string DecryptData(byte[] input, byte[] privateKey, string passPhrase)
    {
      string output;

      PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(new MemoryStream(input)));
      PgpSecretKeyRingBundle pgpSecret = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(new MemoryStream(privateKey)));
      PgpObject pgp = null;

      if (pgpFactory != null)
      {
        pgp = pgpFactory.NextPgpObject();
      }

      PgpEncryptedDataList pgpEncryptedData;
      if (pgp is PgpEncryptedDataList pgpEncryptedDataList)
      {
        pgpEncryptedData = pgpEncryptedDataList;
      }
      else
      {
        pgpEncryptedData = (PgpEncryptedDataList)pgpFactory.NextPgpObject();
      }

      PgpPrivateKey pgpPrivateKey = null;
      PgpPublicKeyEncryptedData pgpPublicKeyEncrypted = null;

      foreach (PgpPublicKeyEncryptedData publicKeyDataItem in pgpEncryptedData.GetEncryptedDataObjects())
      {
        pgpPrivateKey = Utilities.FindSecretKey(pgpSecret, publicKeyDataItem.KeyId, passPhrase.ToCharArray());

        if (pgpPrivateKey != null)
        {
          pgpPublicKeyEncrypted = publicKeyDataItem;
          break;
        }
      }

      if (pgpPrivateKey is null)
      {
        throw new ArgumentException("Secret key for message not found.");
      }

      PgpObjectFactory objectFactory = null;

      using (Stream stream = pgpPublicKeyEncrypted.GetDataStream(pgpPrivateKey))
      {
        objectFactory = new PgpObjectFactory(stream);
      }

      PgpObject message = objectFactory.NextPgpObject();

      if (message is PgpCompressedData compressedData)
      {
        PgpObjectFactory pgpCompressedFactory = null;

        using (Stream compressedDataIn = compressedData.GetDataStream())
        {
          pgpCompressedFactory = new PgpObjectFactory(compressedDataIn);
        }

        message = pgpCompressedFactory.NextPgpObject();

        if (message is PgpOnePassSignatureList)
        {
          message = pgpCompressedFactory.NextPgpObject();
        }

        PgpLiteralData literalData = (PgpLiteralData)message;
        using (Stream literalInputStream = literalData.GetInputStream())
        using (StreamReader reader = new StreamReader(literalInputStream))
        {
          output = reader.ReadToEnd();
        }
      }
      else if (message is PgpLiteralData literalData)
      {
        using (Stream literalInputStream = literalData.GetInputStream())
        using (StreamReader reader = new StreamReader(literalInputStream))
        {
          output = reader.ReadToEnd();
        }
      }
      else if (message is PgpOnePassSignatureList)
      {
        throw new PgpException("Encrypted message contains a signed message - not literal data.");
      }
      else
      {
        throw new PgpException("Message is not a simple encrypted file - type unknown.");
      }

      return output;
    }

    public static bool VerifySignature(Stream inputStream, Stream publicKeyStream)
    {
      inputStream = PgpUtilities.GetDecoderStream(inputStream);

      PgpObjectFactory pgpFactory = new PgpObjectFactory(inputStream);
      PgpCompressedData compressedData = (PgpCompressedData)pgpFactory.NextPgpObject();
      pgpFactory = new PgpObjectFactory(compressedData.GetDataStream());
      PgpOnePassSignatureList signatureList = (PgpOnePassSignatureList)pgpFactory.NextPgpObject();
      PgpOnePassSignature signature = signatureList[0];
      PgpLiteralData literalData = (PgpLiteralData)pgpFactory.NextPgpObject();

      using (Stream input = literalData.GetInputStream())
      {
        PgpPublicKeyRingBundle bundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));
        PgpPublicKey publicKey = bundle.GetPublicKey(signature.KeyId);

        using (Stream fileStream = File.Create(literalData.FileName))
        {
          signature.InitVerify(publicKey);

          int ch;

          while ((ch = input.ReadByte()) >= 0)
          {
            signature.Update((byte)ch);
            fileStream.WriteByte((byte)ch);
          }
        }
      }

      PgpSignatureList pgpSignatureList = (PgpSignatureList)pgpFactory.NextPgpObject();
      PgpSignature pgpSignature = pgpSignatureList[0];

      return signature.Verify(pgpSignature);
    }
  }
}
