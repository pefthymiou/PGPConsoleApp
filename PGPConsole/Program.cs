using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PGPConsole
{
  internal static class Program
  {
    private static void Main(string[] args)
    {
      string filename = "";
      Stream fileStream = File.OpenRead("");
      Stream secretKeyStream = File.OpenRead("");
      Stream publicKeyStream = File.OpenRead("");
      char[] passPhrase = "".ToCharArray();

      try
      {
        
      }
      catch (Exception)
      {
        throw;
      }
    }
  }
}
