using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.WindowsAzure.ServiceRuntime;
using System.Security;

namespace PS30
{
    class Program
    {
        static void Main(string[] args)
        {
            if (RoleEnvironment.IsEmulated)
                return;

            var version = Environment.OSVersion.Version;
            if ((version.Major != 6) && (version.Minor != 1))
                return;

            var temp = Environment.GetEnvironmentVariable("TEMP");
            if (temp == null)
                return;

            // 構成などの設定取得
            var downloadUrl = RoleEnvironment.GetConfigurationSettingValue("PS30.DownloadUrl");
            var userName = RoleEnvironment.GetConfigurationSettingValue("Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountUsername");
            var encPassword = RoleEnvironment.GetConfigurationSettingValue("Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountEncryptedPassword");
            var password = Decrypt(encPassword);

            // ダウンロード
            var msuFileName = Path.Combine(temp, "Windows6.1-PS30.msu");
            var client = new WebClient();
            client.DownloadFile(downloadUrl, msuFileName);

            // WinRMの設定
            ExecuteCommand("netsh", @"advfirewall firewall add rule name=""Windows Remote Management (HTTP-In)"" dir=in program=system action=allow protocol=TCP localport=5985");

            ExecuteCommand("SCHTASKS", string.Format(@"/Create /TN ""WinRM"" /TR ""PowerShell Enable-PSRemoting -Force"" /SC ONCE /ST 23:59:59 /RU {0} /RP {1}", userName, password));
            ExecuteCommand("SCHTASKS", @"/Run /TN ""WinRM""");

            // WMF 3.0 インストール
            ExecuteCommand("sc", @"config wuauserv start= demand");
            ExecuteCommand("wusa.exe", string.Format(@"{0} /quiet", msuFileName));
            ExecuteCommand("sc", @"config wuauserv start= disabled");

        }

        public static string Decrypt(string encryptedString)
        {
            // パスワードを復号
            var store = new X509Store(StoreLocation.LocalMachine); // (StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            var encPasswordBase64 = Convert.FromBase64String(encryptedString);

            var enveloped = new EnvelopedCms();
            enveloped.Decode(encPasswordBase64);
            enveloped.Decrypt(store.Certificates);

            return Encoding.UTF8.GetString(enveloped.ContentInfo.Content);

        }

        public static void ExecuteCommand(string fileName, string arguments)
        {
            using (var p = new Process())
            {
                p.StartInfo.FileName = fileName;
                p.StartInfo.Arguments = arguments;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardInput = true;
                p.Start();
                p.Close();
            }
        }
    }
}
