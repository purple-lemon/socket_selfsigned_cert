using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using vtortola.WebSockets;

namespace CheckCertificate
{
    class Program
    {
        static void Main(string[] args)
        {
            var path = @"F:\Work\Key\CA socket keys\TesCert.pfx";
            X509Certificate2 x509 = new X509Certificate2();
            var data = ReadFile(path);
            x509.Import(data, "1234", X509KeyStorageFlags.DefaultKeySet);


        }

        public void RunServer()
        {
            var server = new WebSocketListener(new IPEndPoint(IPAddress.Any, 8006));
            var rfc6455 = new vtortola.WebSockets.Rfc6455.WebSocketFactoryRfc6455(server);
            server.Standards.RegisterStandard(rfc6455);
            server.Start();
        }

        internal static byte[] ReadFile(string fileName)
        {
            FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read);
            int size = (int)f.Length;
            byte[] data = new byte[size];
            size = f.Read(data, 0, size);
            f.Close();
            return data;
        }
    }
}
