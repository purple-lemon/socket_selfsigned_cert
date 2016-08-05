using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using vtortola.WebSockets;

namespace WebSocketEventListenerSample
{
    class Program
    {
        static void Main(string[] args)
        {
            var r = new Random();
            var utils = new Utils();
            var cert = utils.GetCert();
            // var cert = utils.GetCert(@"F:\Work\Key\CA_socket\ca_lc_child.pfx");
            // var akp = utils.ReadPrivateKey(@"F:\Work\Key\CA_socket\ca_lc.key");
            // var cert = utils.GenerateSelfSignedCertificate("CN=localhost", "CN=localhost", akp);
            // var c = utils.GetCert();
            //if (ssc != null) cert = ssc;

            using (var server = new WebSocketEventListener(new IPEndPoint(IPAddress.Any, 8009), new WebSocketListenerOptions() { SubProtocols = new String[] { "da39a3ee5e" }, NegotiationTimeout = TimeSpan.FromSeconds(30) }, cert))
            {
                server.OnConnect += (ws) => {
                    Console.WriteLine("Connection from " + ws.RemoteEndpoint.ToString());
                    while (true)
                    {
                        Thread.Sleep(5000);
                        try
                        {
                            var d = DateTime.Now.ToLongTimeString();
                            ws.WriteStringAsync(d, CancellationToken.None);
                        }
                        catch (Exception E)
                        {

                        }
                    }
                };
                server.OnDisconnect += (ws) => Console.WriteLine("Disconnection from " + ws.RemoteEndpoint.ToString());
                server.OnError += (ws, ex) =>
                {
                    Console.WriteLine("Error: " + ex.Message);
                };
                server.OnMessage += (ws, msg) =>
                    {

                        Console.WriteLine("Message from [" + ws.RemoteEndpoint + "]: " + msg);
                        ws.WriteStringAsync(new String(msg.Reverse().ToArray()), CancellationToken.None).Wait();
                    };

                server.Start();
                Console.ReadKey(true);
            }
            
        }

        private static void Server_OnMessage(WebSocket webSocket, string message)
        {
            throw new NotImplementedException();
        }
    }
}
