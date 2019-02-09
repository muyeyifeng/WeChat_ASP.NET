<%@ WebHandler Language="C#" Class="Handler" %>
using System;
using System.IO;
using System.Net;
using System.Web;
using System.Xml;
using System.Text;
using System.Configuration;
using System.Data.SqlClient;
using System.Security.Cryptography;
#region
public class Handler : IHttpHandler
{
    public void ProcessRequest(HttpContext context)
    {
        string cmd = context.Request.QueryString["cmd"];
        if (cmd != null)
        {
            switch (cmd)
            {
                case "access_token":
                    WXResponse.access_token(context);
                    break;
                default:
                    break;
            }
        }
        string str =context.Request.QueryString["echostr"];
        if (str != null)
        {
            WXResponse.valid(context);
        }
        else
        {
            try
            {
                StreamReader streamReader = new StreamReader(context.Request.InputStream);
                string xmlData = streamReader.ReadToEnd();
                bool crypt = xmlData.Contains("Encrypt");
                bool dcrypt = xmlData.Contains("MsgType");
                if (dcrypt)
                {
                    WXResponse.responseMsg(context, xmlData, false);
                }
                else if (!dcrypt && crypt)
                {
                    XmlDocument xmlDocument = new XmlDocument();
                    xmlDocument.LoadXml(xmlData);
                    string encrypt = xmlDocument.SelectNodes("/xml/Encrypt")[0].InnerText;
                    string decrypt = WXResponse.decryptAes(encrypt);
                    WXResponse.responseMsg(context, decrypt, true);
                }
            }
            catch { }
        }
    }

    public bool IsReusable
    {
        get
        {
            return false;
        }
    }
}
#endregion
#region
public class WXResponse
{
    //返回UNIX时间
    public static string time()
    {
        DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(new System.DateTime(1970, 1, 1, 0, 0, 0, 0));
        string tm = ((DateTime.Now.Ticks - startTime.Ticks) / 10000000).ToString();
        return tm;
    }
    //验证程序
    public static void valid(HttpContext context)
    {
        string echoStr = context.Request.QueryString["echostr"];
        if (checkSignature(context))
        {
            context.Response.Write(echoStr);
        }
    }
    //返回access_token值
    public static void access_token(HttpContext context)
    {
        string cmd_url = "https://api.weixin.qq.com/cgi-bin/token" +
                               "?grant_type=client_credential" +
                               "&appid=" + ConfigurationManager.AppSettings["AppId"] +
                               "&secret=" + ConfigurationManager.AppSettings["AppSecret"];
        WebRequest webRequest = WebRequest.Create(cmd_url);
        webRequest.ContentType = "text/html;charset=GBK";
        WebResponse webResponse = webRequest.GetResponse();
        Stream stream = webResponse.GetResponseStream();
        StreamReader reader = new StreamReader(stream);
        string result = reader.ReadToEnd();
        string access_token = result.Substring(17, result.Length - 37);
        context.Response.Write(access_token);
    }
    //校验数据
    public static bool checkSignature(HttpContext context)
    {
        string timestamp = context.Request.QueryString["timestamp"];
        string nonce = context.Request.QueryString["nonce"];
        string signature = context.Request.QueryString["signature"];
        string token = ConfigurationManager.AppSettings["ToKen"].ToString();
        string[] arrStr = { timestamp, nonce, token };
        string resStr = "";
        Array.Sort(arrStr);
        foreach(string el in arrStr)
        {
            resStr = resStr + el;
        }
        string tmpStr = HashSHA1(resStr);

        if (tmpStr.Equals(signature.ToUpper()))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    //计算SHA1值
    public static string HashSHA1(string str)
    {
        SHA1CryptoServiceProvider sHA1 = new SHA1CryptoServiceProvider();
        byte[] byteArray = Encoding.UTF8.GetBytes(str);
        byte[] result = sHA1.ComputeHash(byteArray);
        sHA1.Clear();
        StringBuilder hash = new StringBuilder(32);
        foreach (byte hashByte in result)
        {
            hash.Append(hashByte.ToString("x2"));

        }
        return hash.ToString().ToUpper();
    }
    //解密AES
    public static string decryptAes(string aesstr)
    {
        string aeskey = ConfigurationManager.AppSettings["AESKey"].ToString();
        string appid = null;
        string result = Cryptography.AES_decrypt(aesstr, aeskey, ref appid);
        return result;
    }
    //加密AES
    public static string encryptAes(string re_time,string aesstr,string timestamp,string nonce)
    {
        string appid = ConfigurationManager.AppSettings["AppId"].ToString();
        string aeskey = ConfigurationManager.AppSettings["AESKey"].ToString();
        string result = Cryptography.AES_encrypt(aesstr, aeskey, appid);
        string token = ConfigurationManager.AppSettings["ToKen"].ToString();
        string token_result="";
        char[] tch = token.ToCharArray();
        char[] rch = result.ToCharArray();
        int i = 0;
        while (true)
        {
            int t = tch[i] - rch[i];
            if (t > 0)
            {
                token_result = result + token;
                break;
            }
            else if (t < 0)
            {
                token_result = token + result;
                break;
            }
            else
            {
                i++;
            }
        }
        string[] arrStr = { timestamp, nonce, token_result };
        string resStr = "";
        Array.Sort(arrStr);
        foreach (string el in arrStr)
        {
            resStr = resStr + el;

        }
        string msgSignature = HashSHA1(resStr).ToLower();
        result = "<xml>\n" +
        "<Encrypt><![CDATA[" + result + "]]></Encrypt>\n" +
        "<MsgSignature><![CDATA["+msgSignature+"]]></MsgSignature>\n" +
        "<TimeStamp><![CDATA[" + re_time + "]]></TimeStamp>\n" +
        "<Nonce><![CDATA["+nonce+"]]></Nonce>\n" +
        "</xml>";
        return result;
    }
    //回复消息
    public static void responseMsg(HttpContext context,string de_xmlData,bool type)
    {
        XmlDocument xmlDocument = new XmlDocument();
        xmlDocument.LoadXml(de_xmlData);
        //输出日志
        //output("inxmlData", de_xmlData);
        //生成回传数据
        try
        {
            string msgType = xmlDocument.SelectNodes("/xml/MsgType")[0].InnerText;
            XmlNodeList xmlNodeList = xmlDocument.SelectNodes("/xml");
            string toUserName = xmlNodeList[0].ChildNodes[0].InnerText;
            string fromUserName = xmlNodeList[0].ChildNodes[1].InnerText;
            string creatTime = xmlNodeList[0].ChildNodes[2].InnerText;
            string mediaId = "", content = "";
            string re_msgType = "", re_I_mediaId = "", re_V_mediaId = "", re_Vd_mediaId = "", re_thumbMediaId = "";
            switch (msgType)
            {
                case "text":
                    string incontent = xmlNodeList[0].ChildNodes[4].InnerText;
                    content = "Auto Msg Backup!\n" + incontent;
                    re_msgType = "text";
                    break;
                case "voice":
                    mediaId = xmlNodeList[0].ChildNodes[4].InnerText;
                    string format = xmlNodeList[0].ChildNodes[5].InnerText;
                    string recognition = xmlNodeList[0].ChildNodes[7].InnerText;
                    re_msgType = "voice";
                    re_V_mediaId = mediaId;
                    break;
                case "location":
                    string location_X = xmlNodeList[0].ChildNodes[4].InnerText;
                    string location_Y = xmlNodeList[0].ChildNodes[5].InnerText;
                    string scale = xmlNodeList[0].ChildNodes[6].InnerText;
                    string label = xmlNodeList[0].ChildNodes[7].InnerText;
                    content = "纬度：" + location_X + ",经度：" + location_Y;
                    re_msgType = "text";
                    break;
                case "image":
                    string picUrl = xmlNodeList[0].ChildNodes[4].InnerText;
                    mediaId = xmlNodeList[0].ChildNodes[6].InnerText;
                    re_msgType = "image";
                    re_I_mediaId = mediaId;
                    break;
                case "video":
                    mediaId = xmlNodeList[0].ChildNodes[4].InnerText;
                    string thumbMediaId = xmlNodeList[0].ChildNodes[5].InnerText;
                    re_msgType = "video";
                    re_Vd_mediaId = mediaId;
                    re_thumbMediaId = thumbMediaId;
                    break;
                case "event":

                    string _event = xmlNodeList[0].ChildNodes[4].InnerText;
                    string eventKey = xmlNodeList[0].ChildNodes[5].InnerText;
                    if (_event.Equals("subscribe") || _event.Equals("subscribe"))   //订阅状态变更
                    {
                        if (_event.Equals("subscribe"))
                        {
                            content = "欢迎订阅！公众号还在开发中哦！\n目前只是一个优秀的复读机~\no(∩_∩)o";
                            re_msgType = "text";
                        }
                        //以下为数据库操作部分，将用户名保存在数据库中，不是必要的。
                        string connstring = ConfigurationManager.AppSettings["connstring"].ToString();
                        SqlConnection sqlConnection = new SqlConnection(connstring);
                        sqlConnection.Open();
                        SqlCommand sqlCommand = new SqlCommand("update WX set Status ='" + _event + "' where SubUserName ='" + fromUserName + "'", sqlConnection);
                        SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                        sqlDataReader.Close();
                        sqlConnection.Close();
                    }
                    break;
                case "file":
                    string title = xmlNodeList[0].ChildNodes[4].InnerText;
                    string description = xmlNodeList[0].ChildNodes[5].InnerText;
                    string fileKey = xmlNodeList[0].ChildNodes[6].InnerText;
                    string fileMD5 = xmlNodeList[0].ChildNodes[7].InnerText;
                    string fileTotalLen = xmlNodeList[0].ChildNodes[8].InnerText;
                    content = "未知文件!";
                    re_msgType = "text";
                    break;
                default:
                    content = "Unknow messages!";
                    re_msgType = "text";
                    break;
            }
            reply(context,type, fromUserName, toUserName, re_msgType, content, re_I_mediaId, re_V_mediaId, re_Vd_mediaId, re_thumbMediaId);
        }
        catch { }
    }
    //输出日志
    public static void output(string path,string str)
    {
        StreamWriter streamWriter;
        streamWriter = File.CreateText(AppDomain.CurrentDomain.BaseDirectory + "/Log/"+path+time()+".txt");
        streamWriter.WriteLine(str);
        streamWriter.Close();
    }
    //构成消息体
    public static void reply(HttpContext context,bool type,string fromUserName = "", string toUserName = "", string re_msgType = "", string content = "", string re_I_mediaId = "", string re_V_mediaId = "", string re_Vd_mediaId = "", string re_thumbMediaId = "")
    {
        string _content = "";
        string nonce = context.Request.QueryString["nonce"];
        switch (re_msgType)
        {
            case "text":
                _content = "<Content><![CDATA[" + content + "]]></Content>\n";
                break;
            case "image":
                _content = "<Image><MediaId><![CDATA[" + re_I_mediaId + "]]></MediaId></Image>\n";
                break;
            case "voice":
                _content = "<Voice><MediaId><![CDATA[" + re_V_mediaId + "]]></MediaId></Voice>\n";
                break;
            case "video":
                _content = "<Video>\n" +
                    "\t<MediaId><![CDATA[" + re_Vd_mediaId + "]]></MediaId>\n" +
                    "\t<ThumbMediaId><![CDATA[" + re_thumbMediaId + "]]></ThumbMediaId>\n" +
                "</Video>\n";
                break;
            default:
                break;
        }
        string re_time = time();
        string result = "<xml>\n" +
            "<ToUserName><![CDATA[" + fromUserName + "]]></ToUserName>\n" +
            "<FromUserName><![CDATA[" + toUserName + "]]></FromUserName>\n" +
            "<CreateTime><![CDATA[" + re_time + "]]></CreateTime>\n" +
            "<MsgType><![CDATA[" + re_msgType + "]]></MsgType>\n" +
            _content+
            "</xml>";
        if (type)
        {
            result = encryptAes(re_time, result, re_time, nonce);
            context.Response.Write(result);
        }
        else {
            context.Response.Write(result);
        }
        //output("enoutxmlData", result);
    }
}
#endregion
#region
/// <summary>
/// 该部分为直接拷贝腾讯提供的案例程序
/// </summary>
public class Cryptography
{
    public static UInt32 HostToNetworkOrder(UInt32 inval)
    {
        UInt32 outval = 0;
        for (int i = 0; i < 4; i++)
            outval = (outval << 8) + ((inval >> (i * 8)) & 255);
        return outval;
    }

    public static Int32 HostToNetworkOrder(Int32 inval)
    {
        Int32 outval = 0;
        for (int i = 0; i < 4; i++)
            outval = (outval << 8) + ((inval >> (i * 8)) & 255);
        return outval;
    }
    /// <summary>
    /// 解密方法
    /// </summary>
    /// <param name="Input">密文</param>
    /// <param name="EncodingAESKey"></param>
    /// <returns></returns>
    ///
    public static string AES_decrypt(String Input, string EncodingAESKey, ref string appid)
    {
        byte[] Key;
        Key = Convert.FromBase64String(EncodingAESKey + "=");
        byte[] Iv = new byte[16];
        Array.Copy(Key, Iv, 16);
        byte[] btmpMsg = AES_decrypt(Input, Iv, Key);

        int len = BitConverter.ToInt32(btmpMsg, 16);
        len = IPAddress.NetworkToHostOrder(len);

        byte[] bMsg = new byte[len];
        byte[] bAppid = new byte[btmpMsg.Length - 20 - len];
        Array.Copy(btmpMsg, 20, bMsg, 0, len);
        Array.Copy(btmpMsg, 20 + len, bAppid, 0, btmpMsg.Length - 20 - len);
        string oriMsg = Encoding.UTF8.GetString(bMsg);
        appid = Encoding.UTF8.GetString(bAppid);
        return oriMsg;
    }

    public static String AES_encrypt(String Input, string EncodingAESKey, string appid)
    {
        byte[] Key;
        Key = Convert.FromBase64String(EncodingAESKey + "=");
        byte[] Iv = new byte[16];
        Array.Copy(Key, Iv, 16);
        string Randcode = CreateRandCode(16);
        byte[] bRand = Encoding.UTF8.GetBytes(Randcode);
        byte[] bAppid = Encoding.UTF8.GetBytes(appid);
        byte[] btmpMsg = Encoding.UTF8.GetBytes(Input);
        byte[] bMsgLen = BitConverter.GetBytes(HostToNetworkOrder(btmpMsg.Length));
        byte[] bMsg = new byte[bRand.Length + bMsgLen.Length + bAppid.Length + btmpMsg.Length];

        Array.Copy(bRand, bMsg, bRand.Length);
        Array.Copy(bMsgLen, 0, bMsg, bRand.Length, bMsgLen.Length);
        Array.Copy(btmpMsg, 0, bMsg, bRand.Length + bMsgLen.Length, btmpMsg.Length);
        Array.Copy(bAppid, 0, bMsg, bRand.Length + bMsgLen.Length + btmpMsg.Length, bAppid.Length);

        return AES_encrypt(bMsg, Iv, Key);

    }
    private static string CreateRandCode(int codeLen)
    {
        string codeSerial = "2,3,4,5,6,7,a,c,d,e,f,h,i,j,k,m,n,p,r,s,t,A,C,D,E,F,G,H,J,K,M,N,P,Q,R,S,U,V,W,X,Y,Z";
        if (codeLen == 0)
        {
            codeLen = 16;
        }
        string[] arr = codeSerial.Split(',');
        string code = "";
        int randValue = -1;
        Random rand = new Random(unchecked((int)DateTime.Now.Ticks));
        for (int i = 0; i < codeLen; i++)
        {
            randValue = rand.Next(0, arr.Length - 1);
            code += arr[randValue];
        }
        return code;
    }

    private static String AES_encrypt(String Input, byte[] Iv, byte[] Key)
    {
        var aes = new RijndaelManaged();
        //秘钥的大小，以位为单位
        aes.KeySize = 256;
        //支持的块大小
        aes.BlockSize = 128;
        //填充模式
        aes.Padding = PaddingMode.PKCS7;
        aes.Mode = CipherMode.CBC;
        aes.Key = Key;
        aes.IV = Iv;
        var encrypt = aes.CreateEncryptor(aes.Key, aes.IV);
        byte[] xBuff = null;

        using (var ms = new MemoryStream())
        {
            using (var cs = new CryptoStream(ms, encrypt, CryptoStreamMode.Write))
            {
                byte[] xXml = Encoding.UTF8.GetBytes(Input);
                cs.Write(xXml, 0, xXml.Length);
            }
            xBuff = ms.ToArray();
        }
        String Output = Convert.ToBase64String(xBuff);
        return Output;
    }

    private static String AES_encrypt(byte[] Input, byte[] Iv, byte[] Key)
    {
        var aes = new RijndaelManaged();
        //秘钥的大小，以位为单位
        aes.KeySize = 256;
        //支持的块大小
        aes.BlockSize = 128;
        //填充模式
        //aes.Padding = PaddingMode.PKCS7;
        aes.Padding = PaddingMode.None;
        aes.Mode = CipherMode.CBC;
        aes.Key = Key;
        aes.IV = Iv;
        var encrypt = aes.CreateEncryptor(aes.Key, aes.IV);
        byte[] xBuff = null;

        #region 自己进行PKCS7补位，用系统自己带的不行
        byte[] msg = new byte[Input.Length + 32 - Input.Length % 32];
        Array.Copy(Input, msg, Input.Length);
        byte[] pad = KCS7Encoder(Input.Length);
        Array.Copy(pad, 0, msg, Input.Length, pad.Length);
        #endregion

        #region 注释的也是一种方法，效果一样
        //ICryptoTransform transform = aes.CreateEncryptor();
        //byte[] xBuff = transform.TransformFinalBlock(msg, 0, msg.Length);
        #endregion

        using (var ms = new MemoryStream())
        {
            using (var cs = new CryptoStream(ms, encrypt, CryptoStreamMode.Write))
            {
                cs.Write(msg, 0, msg.Length);
            }
            xBuff = ms.ToArray();
        }

        String Output = Convert.ToBase64String(xBuff);
        return Output;
    }

    private static byte[] KCS7Encoder(int text_length)
    {
        int block_size = 32;
        // 计算需要填充的位数
        int amount_to_pad = block_size - (text_length % block_size);
        if (amount_to_pad == 0)
        {
            amount_to_pad = block_size;
        }
        // 获得补位所用的字符
        char pad_chr = chr(amount_to_pad);
        string tmp = "";
        for (int index = 0; index < amount_to_pad; index++)
        {
            tmp += pad_chr;
        }
        return Encoding.UTF8.GetBytes(tmp);
    }
    /**
     * 将数字转化成ASCII码对应的字符，用于对明文进行补码
     *
     * @param a 需要转化的数字
     * @return 转化得到的字符
     */
    static char chr(int a)
    {

        byte target = (byte)(a & 0xFF);
        return (char)target;
    }
    private static byte[] AES_decrypt(String Input, byte[] Iv, byte[] Key)
    {
        RijndaelManaged aes = new RijndaelManaged();
        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.Key = Key;
        aes.IV = Iv;
        var decrypt = aes.CreateDecryptor(aes.Key, aes.IV);
        byte[] xBuff = null;
        using (var ms = new MemoryStream())
        {
            using (var cs = new CryptoStream(ms, decrypt, CryptoStreamMode.Write))
            {
                byte[] xXml = Convert.FromBase64String(Input);
                byte[] msg = new byte[xXml.Length + 32 - xXml.Length % 32];
                Array.Copy(xXml, msg, xXml.Length);
                cs.Write(xXml, 0, xXml.Length);
            }
            xBuff = decode2(ms.ToArray());
        }
        return xBuff;
    }
    private static byte[] decode2(byte[] decrypted)
    {
        int pad = (int)decrypted[decrypted.Length - 1];
        if (pad < 1 || pad > 32)
        {
            pad = 0;
        }
        byte[] res = new byte[decrypted.Length - pad];
        Array.Copy(decrypted, 0, res, 0, decrypted.Length - pad);
        return res;
    }
}
#endregion
