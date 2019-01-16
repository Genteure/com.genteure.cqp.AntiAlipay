using DnsClient;
using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using ZXing;

namespace com.genteure.cqp.AntiAlipay
{
    internal static class Main
    {
        internal const string APP_ID = "com.genteure.cqp.AntiAlipay";

        private static string DB_File;
        private static long[] GroupList = { 95349372L, 627565437L, 423768065L, 549858724L };
        private static string[] DomainBlacklist = { "tbcache.com.", "alipaydns.com." };

        [DllExport("_eventEnable", CallingConvention.StdCall)]
        public static CoolQApi.Event ProcessEnable()
        {
            DB_File = CoolQApi.GetAppDirectory() + "db.txt";

            try
            {
                GroupList = File.ReadAllLines(CoolQApi.GetAppDirectory() + "group.txt").Select(long.Parse).ToArray();
            }
            catch (Exception ex)
            {
                CoolQApi.AddLog(CoolQApi.LogLevel.Warning, "群号初始化错误", ex.ToString());
            }

            try
            {
                DomainBlacklist = File.ReadAllLines(CoolQApi.GetAppDirectory() + "domain.txt");
            }
            catch (Exception ex)
            {
                CoolQApi.AddLog(CoolQApi.LogLevel.Warning, "域名黑名单初始化错误", ex.ToString());
            }
            return CoolQApi.Event.Ignore;
        }

        [DllExport("_eventGroupMsg", CallingConvention.StdCall)]
        public static CoolQApi.Event ProcessGroupMessage(int subType, int messageId, long fromGroup,
            long fromQQ, string fromAnonymous, string msg, int font)
        {
            try
            {
                if (!GroupList.Any(x => x == fromGroup))
                {
                    return CoolQApi.Event.Ignore;
                }

                var matches = REGEX_GETIMAGE.Matches(msg);

                if (matches.Count == 0)
                {
                    return CoolQApi.Event.Ignore;
                }

                bool flag_isAlipay = false;

                for (int i = 0; i < matches.Count; i++)
                {
                    if (IsAlipay(matches[i].Groups[1].Value))
                    {
                        flag_isAlipay = true;
                        break;
                    }
                }

                if (flag_isAlipay)
                {
                    string qqstring = fromQQ.ToString();
                    if (File.ReadAllLines(DB_File).Any(x => x == qqstring))
                    {
                        // 文件里有这个人，踢出群
                        CoolQApi.SendGroupMsg(fromGroup, "严格禁止支付宝类二维码小广告。第二次触发，已自动踢出群。");
                        CoolQApi.SetGroupKick(fromGroup, fromQQ);
                    }
                    else
                    {
                        // 文件里没有这个人，警告并禁言
                        File.AppendAllLines(DB_File, new[] { qqstring });
                        CoolQApi.SendGroupMsg(fromGroup, "严格禁止支付宝类二维码小广告。第一次禁言，第二次自动踢出群。");
                        CoolQApi.SetGroupBan(fromGroup, fromQQ, 60 * 60 * 2); // 禁言 2 小时
                    }
                    Task.Run(async () =>
                    {
                        await Task.Delay(3000);
                        CoolQApi.DeleteMsg(messageId);
                    });
                }
                return CoolQApi.Event.Ignore;
            }
            catch (Exception ex)
            {
                CoolQApi.AddLog(CoolQApi.LogLevel.Error, "出错", ex.ToString());
                return CoolQApi.Event.Ignore;
            }
        }

        private static bool IsAlipay(string filename)
        {
            try
            {
                const int HTTP_TIMEOUT = 10 * 1000;
                const string HTTP_USERAGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36";

                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data", "image", filename + ".cqimg");
                string url = CQIMG_REGEX.Match(File.ReadAllText(path)).Groups[1].Value;
                var request = (HttpWebRequest)WebRequest.Create(url);
                request.Timeout = HTTP_TIMEOUT;
                request.UserAgent = HTTP_USERAGENT;

                var response = (HttpWebResponse)request.GetResponse();
                var image = (Bitmap)Image.FromStream(response.GetResponseStream());

                IBarcodeReader reader = new BarcodeReader();
                var result = reader.Decode(image);

                if (result != null)
                {
                    string host = new Uri(result.Text).Host;
                    var dnsresult = new LookupClient().QueryServer(dnsserver, host, QueryType.CNAME);
                    var cnameDomain = dnsresult.Answers.CnameRecords().FirstOrDefault()?.CanonicalName?.Value;
                    return DomainBlacklist.Any(x => cnameDomain.EndsWith(x));
                }
                else
                {
                    return false;
                }
            }
            catch (UriFormatException)
            {
                return false;
            }
            catch (Exception ex)
            {
                CoolQApi.AddLog(CoolQApi.LogLevel.Warning, "检查网址错误", ex.ToString());
                return false;
            }
        }

        private static readonly IPAddress[] dnsserver = { IPAddress.Parse("119.29.29.29"), IPAddress.Parse("114.114.114.114") };
        private static readonly Regex REGEX_GETIMAGE = new Regex(@"\[CQ:image,file=(.{32}\.(?:png|jpg|gif))\]", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex CQIMG_REGEX = new Regex("^url=(http.*)$", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    }
}
