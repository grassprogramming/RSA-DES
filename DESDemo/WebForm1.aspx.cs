using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace DESDemo
{
    public partial class WebForm1 : System.Web.UI.Page
    {
        private static string key = "paul12030524";
        private static string data = "hello world,2016!你好,世界!";
        protected void Page_Load(object sender, EventArgs e)
        {
            string M = DesEncrypt(key, data);
            Response.Write("加密后明文：" + M +"</br>");
            string C = RsaEncrypt(key);
            Response.Write("加密后秘钥:" + C + "</br>");
            string CC = RsaDecrypt(C);
            Response.Write("解密后秘钥:" + CC + "</br>");
            string MM = DesDecrypt(CC, M);
            Response.Write("解密后明文：" + MM + "</br>");
            
        }

        public static string RsaEncrypt(string encryptString)
        {
            //加密
            string fileName = @"E:\BlogDemo\DESDemo\DESDemo\CAPublicKey.cer";  //公钥
            String password = "111111";
            string strdata = encryptString;
            byte[] data = Encoding.GetEncoding("UTF-8").GetBytes(strdata);
            X509Certificate2 objx5092;
            if (string.IsNullOrEmpty(password))
                objx5092 = new X509Certificate2(fileName);
            else
                objx5092 = new X509Certificate2(fileName, password);
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(objx5092.PublicKey.Key.ToXmlString(false));  //获取公钥

            //加密块最大长度限制，如果加密数据的长度超过 秘钥长度/8-11，会引发长度不正确的异常，所以进行数据的分块加密
            int MaxBlockSize = rsa.KeySize / 8 - 11;
            //正常长度
            if (data.Length <= MaxBlockSize)
            {
                byte[] hashvalueEcy = rsa.Encrypt(data, false); //加密
                return Convert.ToBase64String(hashvalueEcy);
            }
            //长度超过正常值
            else
            {
                using (MemoryStream PlaiStream = new MemoryStream(data))
                using (MemoryStream CrypStream = new MemoryStream())
                {
                    Byte[] Buffer = new Byte[MaxBlockSize];
                    int BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);
                    while (BlockSize > 0)
                    {
                        Byte[] ToEncrypt = new Byte[BlockSize];
                        Array.Copy(Buffer, 0, ToEncrypt, 0, BlockSize);

                        Byte[] Cryptograph = rsa.Encrypt(ToEncrypt, false);
                        CrypStream.Write(Cryptograph, 0, Cryptograph.Length);
                        BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);
                    }
                    return Convert.ToBase64String(CrypStream.ToArray(), Base64FormattingOptions.None);
                }


            }
        }


        public static string RsaDecrypt(string decryptString)
        {
            //解密
            string fileName = @"E:\BlogDemo\DESDemo\DESDemo\CAPrivateKey.pfx";  //私钥
            String password = "Yanpeng24*";
            X509Certificate2 objx5092;
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            if (string.IsNullOrEmpty(password))
                objx5092 = new X509Certificate2(fileName);
            else
                objx5092 = new X509Certificate2(fileName, password);
            rsa = objx5092.PrivateKey as RSACryptoServiceProvider;

            int MaxBlockSize = rsa.KeySize / 8;    //解密块最大长度限制
            //正常解密
            if (decryptString.Length <= MaxBlockSize)
            {
                byte[] hashvalueDcy = rsa.Decrypt(Convert.FromBase64String(decryptString), false);//解密
                return Encoding.GetEncoding("UTF-8").GetString(hashvalueDcy);
            }
            //分段解密
            else
            {
                using (MemoryStream CrypStream = new MemoryStream(Convert.FromBase64String(decryptString)))
                using (MemoryStream PlaiStream = new MemoryStream())
                {
                    Byte[] Buffer = new Byte[MaxBlockSize];
                    int BlockSize = CrypStream.Read(Buffer, 0, MaxBlockSize);

                    while (BlockSize > 0)
                    {
                        Byte[] ToDecrypt = new Byte[BlockSize];
                        Array.Copy(Buffer, 0, ToDecrypt, 0, BlockSize);

                        Byte[] Plaintext = rsa.Decrypt(ToDecrypt, false);
                        PlaiStream.Write(Plaintext, 0, Plaintext.Length);

                        BlockSize = CrypStream.Read(Buffer, 0, MaxBlockSize);
                    }

                    string output = Encoding.GetEncoding("UTF-8").GetString(PlaiStream.ToArray());
                    return output;
                    //List<BaseInfo> baseinfo = JsonConvert.DeserializeObject<List<BaseInfo>>(output);
                    //image1.Src = "data:image/png;base64," + baseinfo[0].Picture;
                }
            }
        }

        /**/
        /// <summary> 
        /// DES加密 
        /// </summary> 
        /// <param name="encryptString"></param> 
        /// <returns></returns> 
        public static string DesEncrypt(string key,string encryptString)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key.Substring(0, 8));
            byte[] keyIV = keyBytes;
            byte[] inputByteArray = Encoding.UTF8.GetBytes(encryptString);
            DESCryptoServiceProvider provider = new DESCryptoServiceProvider();
            MemoryStream mStream = new MemoryStream();
            CryptoStream cStream = new CryptoStream(mStream, provider.CreateEncryptor(keyBytes, keyIV), CryptoStreamMode.Write);
            cStream.Write(inputByteArray, 0, inputByteArray.Length);
            cStream.FlushFinalBlock();
            return Convert.ToBase64String(mStream.ToArray());
        }

        /**/
        /// <summary> 
        /// DES解密 
        /// </summary> 
        /// <param name="decryptString"></param> 
        /// <returns></returns> 
        public static string DesDecrypt(string key,string decryptString)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key.Substring(0, 8));
            byte[] keyIV = keyBytes;
            byte[] inputByteArray = Convert.FromBase64String(decryptString);
            DESCryptoServiceProvider provider = new DESCryptoServiceProvider();
            MemoryStream mStream = new MemoryStream();
            CryptoStream cStream = new CryptoStream(mStream, provider.CreateDecryptor(keyBytes, keyIV), CryptoStreamMode.Write);
            cStream.Write(inputByteArray, 0, inputByteArray.Length);
            cStream.FlushFinalBlock();
            return Encoding.UTF8.GetString(mStream.ToArray());
        }
    }
}