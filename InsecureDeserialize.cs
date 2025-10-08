using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace VulnerableTelerikDemo
{
    public static class InsecureDeserialize
    {
        // Call this from somewhere, or keep as a utility SAST can see.
        public static object FromBase64(string b64)  // <- SAST should still flag usage
        {
            var data = Convert.FromBase64String(b64 ?? "");
            using var ms = new MemoryStream(data);
#pragma warning disable SYSLIB0011
            var bf = new BinaryFormatter();          // <- flagged API
            return bf.Deserialize(ms);               // <- critical sink
#pragma warning restore SYSLIB0011
        }
    }
}
