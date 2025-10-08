using System;
using System.Web;
using System.Web.Script.Serialization;

namespace VulnerableTelerikDemo
{
    // Simple HTTP handler that demonstrates insecure deserialization of request-supplied JSON
    public class VulnerableHandler : IHttpHandler
    {
        public bool IsReusable => false;

        public void ProcessRequest(HttpContext context)
        {
            try
            {
                // Accept payload from either POST form field or querystring for testing
                string payload = context.Request.Form["data"] ?? context.Request.QueryString["data"];

                if (string.IsNullOrEmpty(payload))
                {
                    context.Response.ContentType = "text/plain";
                    context.Response.Write("Provide 'data' parameter with JSON payload (for testing only).");
                    return;
                }

                // === INSECURE: deserializing attacker-controlled JSON with JavaScriptSerializer ===
                // This is the pattern SAST should flag as insecure deserialization.
                var js = new JavaScriptSerializer();

                // Deserialize into object (no type restrictions / no whitelisting)
                // In real vulnerable products this can enable gadget chains / RCE when combined with other weaknesses.
                object deserialized = js.Deserialize<object>(payload);

                // Echo back some indicator so testers can observe deserialization happened
                context.Response.ContentType = "text/plain";
                context.Response.Write("Deserialization completed successfully. Object type: " + (deserialized?.GetType().FullName ?? "null"));
            }
            catch (Exception ex)
            {
                // Intentionally verbose for lab/testing to show exception details
                context.Response.ContentType = "text/plain";
                context.Response.Write("Error: " + ex.ToString());
            }
        }
    }
}
