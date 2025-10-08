using System;
using System.Web;
using System.Web.Script.Serialization;

namespace VulnerableTelerikDemo
{
    public class VulnerableHandler : IHttpHandler
    {
        public bool IsReusable => false;

        public void ProcessRequest(HttpContext context)
        {
            string payload = context.Request.Form["data"] ?? context.Request.QueryString["data"];
            if (string.IsNullOrEmpty(payload))
            {
                context.Response.ContentType = "text/plain";
                context.Response.Write("Provide 'data' param.");
                return;
            }

            // INSECURE: untrusted deserialization
            var js = new JavaScriptSerializer();
            object obj = js.Deserialize<object>(payload);  // <- SAST sink

            context.Response.ContentType = "text/plain";
            context.Response.Write("OK: " + (obj?.GetType().FullName ?? "null"));
        }
    }
}
