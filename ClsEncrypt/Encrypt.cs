using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace ClsEncrypt
{
  public class MyEncrypt
  {

    /// <summary>
    /// 
    /// </summary>
    /// <param name="encryptedStr"></param>
    /// <returns></returns>
    public static string DecryptByDPAPI(string encryptedStr)
    {
      log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
      var entrpy = "浦和うなこちゃんはやなせたかし";
      entrpy = string.Concat(entrpy.Reverse());
      if (encryptedStr.ToLower().Contains(@"data source")) {
        // log.Debug($"src:[{encryptedStr}]");
        log.Warn($"DPAPI check:[{myEncryptEx(encryptedStr, entrpy)}]");
        return encryptedStr;
      }
      return myDecryptEx(encryptedStr, entrpy);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="str"></param>
    /// <param name="entropy"></param>
    /// <returns></returns>
    private static string myEncryptEx(string str, string entropy)
    {
      log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
      var encryptedStr = "";
      try {
        var entropyBytes = Encoding.UTF8.GetBytes(entropy);
        var dataBytes = Encoding.UTF8.GetBytes(str);
        var encryptedBytes = ProtectedData.Protect(dataBytes, entropyBytes, DataProtectionScope.LocalMachine);

        encryptedStr = Convert.ToBase64String(encryptedBytes);

      } catch (Exception ex) {
        log.Error("encrypt failed.", ex);
        // Console.WriteLine(ex.ToString());
        // throw;
      }
      return encryptedStr;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="base64Str"></param>
    /// <param name="entropy"></param>
    /// <returns></returns>
    private static string myDecryptEx(string base64Str, string entropy)
    {
      log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
      var decryptedStr = base64Str;

      if (string.IsNullOrEmpty(base64Str)) {
        return decryptedStr;
      }

      try {
        var entropyBytes = Encoding.UTF8.GetBytes(entropy);
        var encryptedBytes = Convert.FromBase64String(base64Str);
        var decryptedBytes = ProtectedData.Unprotect(encryptedBytes, entropyBytes, DataProtectionScope.LocalMachine);

        decryptedStr = Encoding.UTF8.GetString(decryptedBytes);

      } catch (Exception ex) {
        log.Error($"DPAPI check:[{myEncryptEx(base64Str,entropy)}]", ex);
        // Console.WriteLine(ex.ToString());
        // throw;
      }
      return decryptedStr;
    }

  }
}
