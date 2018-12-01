using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.CommandLineUtils;
using Newtonsoft.Json.Linq;

namespace NCMToMp3
{
    static class Program
    {
        private static readonly byte[] AesCoreKey = { 0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57 };
        private static readonly byte[] AesModifyKey = { 0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28};
        
        static async Task<int> Main(string[] args)
        {
            var app = new CommandLineApplication();
            var helpOption = app.HelpOption("-h|--help");
            var fileOption = app.Option("-f|--file <FILE>", "指定要转换的 NCM 文件路径，输出路径默认为 NCM 文件所在的文件夹.", CommandOptionType.SingleValue);
            var folderOption = app.Option("-d|--dir <DIRECTORY>", "指定要转换的 NCM 文件存放的文件夹路径，输出路径默认为 NCM 文件所在的文件夹.", CommandOptionType.SingleValue);
            
            app.OnExecute(() =>
            {
                if (fileOption.HasValue())
                {
                    if (!File.Exists(fileOption.Value()))
                    {
                        Console.WriteLine("文件路径不存在，请指定有效的路径.");
                        return -1;
                    }
                    
                    Console.WriteLine($"正在处理文件: \"{fileOption.Value()}\"...");
                    ProcessFile(fileOption.Value());
                    Console.WriteLine("处理完成.");
                    return 0;
                }

                if (folderOption.HasValue())
                {
                    if (!Directory.Exists(folderOption.Value()))
                    {
                        Console.WriteLine("文件夹路径不存在，请指定有效的路径.");
                        return -1;
                    }
                    
                    Console.WriteLine("正在扫描文件夹...");
                    var files = FindFiles(folderOption.Value(), new[]{"*.ncm"});
                    Console.WriteLine($"一共搜索到 {files["*.ncm"].Count} 个 NCM 加密的音乐文件.");
                    Console.WriteLine("正在开始转换，请稍候...");

                    int allFileCount = 0;
                    var result = Parallel.ForEach<string,int>(files["*.ncm"], 
                        localInit: () => 0, body: (fileName,parallelStatus,index,fileCount)=>
                        {
                            try
                            {
                                ProcessFile(fileName);
                                return 1;
                            }
                            catch (Exception)
                            {
                                return 0;
                            }
                        },
                        localFinally: fileCount =>
                        {
                            Interlocked.Add(ref allFileCount, fileCount);
                        } );
                    
                    if (result.IsCompleted)
                    {
                        Console.WriteLine("所有 NCM 文件已经成功转换...");
                    }
                    else
                    {
                        if (allFileCount != files.Count)
                        {
                            Console.WriteLine($"一共有 {files["*.ncm"].Count - allFileCount} 个文件转换失败..");
                        }
                    }
                }

                return -1;
            });

            return await Task.FromResult(app.Execute(args));
        }

        private static void ProcessFile(string filePath)
        {
            var fs = File.Open(filePath,FileMode.Open);

            var lenBytes = new byte[4];
            fs.Read(lenBytes);
            if (BitConverter.ToInt32(lenBytes) != 0x4e455443)
            {
                Console.WriteLine("输入文件并非网易云加密文件.");
                return;
            }
            
            fs.Read(lenBytes);
            if (BitConverter.ToInt32(lenBytes) != 0x4d414446)
            {
                Console.WriteLine("输入文件并非网易云加密文件.");
                return;
            }

            fs.Seek(2, SeekOrigin.Current);
            fs.Read(lenBytes);
            var keyBytes = new byte[BitConverter.ToInt32(lenBytes)];
            fs.Read(keyBytes);

            for (int i = 0; i < keyBytes.Length; i++)
            {
                keyBytes[i] ^= 0x64;
            }

            // 此处解析出来的值应该为减去字符串 "neteasecloudmusic" 长度之后的信息
            var deKeyDataBytes = GetBytesByOffset(DecryptAex128Ecb(AesCoreKey,keyBytes),17);
            
            fs.Read(lenBytes);
            var modifyData = new byte[BitConverter.ToInt32(lenBytes)];
            fs.Read(modifyData);
            
            for (int i = 0; i < modifyData.Length; i++)
            {
                modifyData[i] ^= 0x63;
            }

            // 从 Base64 字符串进行解码
            var decryptBase64Bytes = Convert.FromBase64String(Encoding.UTF8.GetString(GetBytesByOffset(modifyData,22)));
            var decryptModifyData = DecryptAex128Ecb(AesModifyKey, decryptBase64Bytes);
            // 确定歌曲后缀名
            var musicJson = JObject.Parse(Encoding.UTF8.GetString(GetBytesByOffset(decryptModifyData, 6)));
            
            // 歌曲 JSON 数据读取
            var extensions = musicJson.SelectToken("$.format").Value<string>();
            
            // CRC 校验
            fs.Seek(4, SeekOrigin.Current);
            fs.Seek(5, SeekOrigin.Current);

            // 获取专辑图像数据
            fs.Read(lenBytes);
            var imgLength = BitConverter.ToInt32(lenBytes);
            var imageBytes = new byte[imgLength];
            if (imgLength > 0)
            {
                fs.Read(imageBytes);
            }

            var box = BuildKeyBox(deKeyDataBytes);

            var n = 0x8000;
            // 输出歌曲文件
            using (var outputFile = File.Create(Path.Combine(Path.GetDirectoryName(filePath),$"{Path.GetFileNameWithoutExtension(filePath)}.{extensions}")))
            {
                while (true)
                {
                    var tb = new byte[n];
                    var result = fs.Read(tb);
                    if(result <= 0) break;

                    for (int i = 0; i < n; i++)
                    {
                        var j = (byte) ((i + 1) & 0xff);
                        tb[i] ^= box[box[j] + box[(box[j] + j) & 0xff] & 0xff];
                    }
                    
                    outputFile.Write(tb);
                }
                
                outputFile.Flush();
            }
            
            fs.Close();
        }

        private static byte[] DecryptAex128Ecb(byte[] keyBytes, byte[] data)
        {
            var aes = Aes.Create();
            if (aes != null)
            {
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.ECB;
                using (var decryptor = aes.CreateDecryptor(keyBytes, null))
                {
                    byte[] result = decryptor.TransformFinalBlock(data, 0, data.Length);
                    return result;
                }
            }

            return null;
        }

        private static byte[] BuildKeyBox(byte[] key)
        {
            byte[] box = new byte[256];
            for (int i = 0; i < 256; ++i)
            {
                box[i] = (byte) i;
            }

            byte keyLength = (byte)key.Length;
            byte c;
            byte lastByte = 0;
            byte keyOffset = 0;
            byte swap;
            
            for (int i = 0; i < 256; ++i)
            {
                swap = box[i];
                c = (byte)((swap + lastByte + key[keyOffset++]) & 0xff);

                if (keyOffset >= keyLength)
                {
                    keyOffset = 0;
                }

                box[i] = box[c];
                box[c] = swap;
                lastByte = c;
            }
            
            return box;
        }

        private static byte[] GetBytesByOffset(byte[] srcBytes, int offset = 0,long length = 0)
        {
            if (length == 0)
            {
                var resultBytes = new byte[srcBytes.Length - offset];
                Array.Copy(srcBytes,offset,resultBytes,0,srcBytes.Length - offset);
                return resultBytes;
            }

            var resultBytes2 = new byte[length];
            Array.Copy(srcBytes,0,resultBytes2,0,length);
            return resultBytes2;
        }

        private static Dictionary<string, List<string>> FindFiles(string dirPath, string[] extensions)
        {
            if (extensions != null && extensions.Length != 0)
            {
                var files = new Dictionary<string, List<string>>();

                foreach (var extension in extensions)
                {
                    var result = new List<string>();
                    SearchFile(result,dirPath,extension);
                    files.Add(extension,result);
                }

                return files;
            }

            return null;
        }
        
        private static void SearchFile(List<string> files, string folder, string extension)
        {
            foreach (var file in Directory.GetFiles(folder,extension))
            {
                files.Add(file);
            }

            try
            {
                foreach (var directory in Directory.GetDirectories(folder))
                {
                    SearchFile(files,directory,extension);
                }
            }
            catch (Exception)
            {
                
            }
        }
    }
}