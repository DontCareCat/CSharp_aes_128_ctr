using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using static System.Console;

namespace openssl_aes_128_ctr
{
    class Program
    {
        static bool encrypt;
        static string in_path = string.Empty;
        static string out_path = string.Empty;
        static string password = string.Empty;
        static string IV = string.Empty;
        static string InputText = string.Empty;
        static Chilkat.Crypt2 AES= new Chilkat.Crypt2();
        static void Main(string[] args)
        {
            //args = new string[] { "-e", "-in", "C:\\Users\\DontCareCat\\Desktop\\exorcism.txt", "-p", "p@ssw0rd", "-iv", "12345" };

            ContextSetup(args);
            if ( (in_path == string.Empty && InputText == string.Empty) || out_path == string.Empty || password == string.Empty || IV == string.Empty)
            {
                WriteLine("Cannot continue due to errors above");
            }
            else
            {
                string output = null;
                if (encrypt)
                {
                    if (in_path == "console")
                    {
                        Encrypt(InputText, out output);
                    }
                    else
                    {
                        Encrypt(File.ReadAllText(in_path), out output);
                    }
                    if (out_path == "console")
                    {
                        //WriteLine(output);
                        int j = 0;
                        string buffer = null;
                        for(int i=0;i<output.Length;i++)
                        {
                            if (j < 63)
                            {
                                buffer += output[i];
                                j++;
                            }
                            else
                            {
                                buffer += $"\n{output[i]}";
                                j = 0;
                            }
                        }
                        WriteLine(buffer);
                    }
                    else
                    {
                        int j = 0;
                        string buffer = null;
                        for (int i = 0; i < output.Length; i++)
                        {
                            if (j < 63)
                            {
                                buffer += output[i];
                                j++;
                            }
                            else
                            {
                                buffer += $"\n{output[i]}";
                                j = 0;
                            }
                        }
                        File.WriteAllText(out_path, buffer);
                    }
                }
                else
                {
                    if (in_path == "console")
                    {
                        Dectypt(InputText, out output);
                    }
                    else
                    {
                        Dectypt(File.ReadAllText(in_path), out output);
                    }
                    if (out_path == "console")
                    {
                        WriteLine(output);
                    }
                    else
                    {
                        File.WriteAllText(out_path, output);
                    }
                }
            }
        }
        static void Encrypt(string Input, out string Output)
        {
            Output = AES.EncryptStringENC(Input);
        }
        static void Dectypt(string Input, out string Output)
        {
            Output = AES.DecryptStringENC(Input);
        }
        static void ContextSetup(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help")
            {
                GetHelp();
            }
            else
            {
                out_path = "console";
                in_path = "console";
                for (int i = 0; i < args.Length; i++)
                {
                    try
                    {
                        switch (args[i])
                        {
                            case "-e":
                                encrypt = true;
                                break;
                            case "-d":
                                encrypt = false;
                                break;
                            case "-in":
                                i++;
                                if (File.Exists(args[i]))
                                {
                                    string[] NoBackSlashess = args[i].Split('\\');
                                    if (NoBackSlashess[NoBackSlashess.Length - 1].Split('.')[1] == "txt")
                                        in_path = args[i];
                                    else
                                    {
                                        WriteLine("ERR! input file must be in *.txt format!");
                                        in_path = string.Empty;
                                    }
                                }
                                else
                                {
                                    WriteLine($"ERR! File {args[i]} does not exist!");
                                    in_path = string.Empty;
                                }
                                break;
                            case "-out":
                                i++;
                                    string[] NoBackSlashes = args[i].Split('\\');
                                    if (NoBackSlashes[NoBackSlashes.Length - 1].Split('.')[1] == "txt")
                                        out_path = args[i];
                                    else
                                    {
                                        WriteLine("ERR! input file must be in *.txt format!");
                                        out_path = string.Empty;
                                    }
                                break;
                            case "-p":
                                i++;
                                if (args[i].Length <= 16 && args[i].Length >= 1)
                                {
                                    bool isAscii = true;
                                    foreach (char c in args[i])
                                        if (c < 32 || c >= 127)
                                            isAscii = false;
                                    if (isAscii)
                                    {
                                        password = args[i].PadLeft(16, '0');
                                    }
                                    else
                                        WriteLine("ERR! Password must be ASCII encoded");
                                }
                                else
                                    WriteLine("ERR! Password must be 1 to 16 chars long!");

                                break;
                            case "-iv":
                                i++;
                                args[i] = args[i].ToUpper();
                                bool is_hex = true;
                                foreach (char c in args[i])
                                {
                                    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
                                    {
                                        is_hex = false;
                                    }
                                }
                                if (is_hex)
                                    IV = args[i];
                                break;
                            default:
                                if (!encrypt)
                                {
                                    Span<byte> buffer = new Span<byte>(new byte[args[i].Length]);
                                    if (Convert.TryFromBase64String(args[i], buffer, out int BytesParsed))
                                    {
                                        InputText = args[i];
                                    }
                                }
                                else
                                {
                                    InputText = args[i];
                                }
                                break;
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteLine("Execution stopped due to error below:");
                        WriteLine(ex.Message);
                        GetHelp();
                    }
                }
                AES.CryptAlgorithm = "aes";
                AES.CipherMode = "ctr";
                AES.KeyLength = 128;
                AES.EncodingMode = "base64";
                AES.SetEncodedIV(IV, "ascii");
                AES.SetEncodedKey(password, "ascii");
                AES.HashAlgorithm = "md5";
            }
        }
        static void GetHelp()
        {
            string[] help = {"USAGE: openssl_aes_128_ctr.exe -[e,d] [-in /input/path/] [-out /out/path] -p <password> -iv <IV>",
                "Arguments:",
                "   -e          -- encrypt",
                "   -d          -- dectypt",
                "   -in         -- use input file. If absent, text from console will be used as input",
                "   -out        -- write output to file. If absent, output will be written to console",
                "   -p          -- used to specify passphrase for algorithm",
                "   -iv         -- initialization vector",
                "   <password>  -- ASCII string. Up to 16 chars",
                "   <IV>        -- The actual IV to use: this must be represented as a string comprised only of hex digits."};
            foreach (string help_str in help)
                WriteLine(help_str);
        }
    }
}
