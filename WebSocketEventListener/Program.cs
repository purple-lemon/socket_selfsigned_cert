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
            //CheckTask();
            //return;

            var tokenSource = new CancellationTokenSource();
            var token = tokenSource.Token;
            var r = new Random();
            var utils = new Utils();
            var cert = utils.GetCert();
            var sockets = new List<WebSocket>();


            using (var server = new WebSocketEventListener(new IPEndPoint(IPAddress.Any, 8009), new WebSocketListenerOptions() { SubProtocols = new String[] { "123456" }, NegotiationTimeout = TimeSpan.FromSeconds(30) }, cert))
            {
                server.OnConnect += (ws) => {
                    sockets.Add(ws);
                    Console.WriteLine("Connection from " + ws.RemoteEndpoint.ToString());
                    //while (true)
                    //{
                    //    Thread.Sleep(5000);
                    //    try
                    //    {
                    //        var d = DateTime.Now.ToLongTimeString();
                    //        ws.WriteStringAsync(d, CancellationToken.None);
                    //    }
                    //    catch (Exception E)
                    //    {

                    //    }
                    //}
                };
                server.OnDisconnect += (ws) =>
                {
                    sockets.Remove(ws);
                    Console.WriteLine("Disconnection from " + ws.RemoteEndpoint.ToString());
                };
                server.OnError += (ws, ex) =>
                {
                    Console.WriteLine("Error: " + ex.Message);
                };
                server.OnMessage += (ws, msg) =>
                    {
                        if (token.IsCancellationRequested)
                        {
                            
                        }
                        Console.WriteLine("Message from [" + ws.RemoteEndpoint + "]: " + msg);
                        var wsContext = ws;
                        var task = Task.Factory.StartNew(() =>
                        {
                            var util = new Utils();
                            // util.ProcessMessage(wsContext);
                            foreach (var w in sockets)
                            {
                                if (w != ws)
                                {
                                    w.WriteString("new guy connected");
                                }
                            }
                        }, token);
                        
                        //ws.WriteStringAsync(new String(msg.Reverse().ToArray()), CancellationToken.None).Wait();
                    };

                server.Start();
                Console.ReadKey(true);
                tokenSource.Cancel();
                Console.ReadKey(true);
            }
            
        }

        private static void Server_OnMessage(WebSocket webSocket, string message)
        {
            throw new NotImplementedException();
        }

        public static void CheckTask()
        {
            var cancS = new CancellationTokenSource();
            var task = Task.Factory.StartNew(() =>
            {
                while (true)
                {
                    Console.WriteLine(DateTime.Now.ToLongTimeString());
                    Thread.Sleep(1000);
                }
            }, cancS.Token);

            Console.ReadKey();
            cancS.Cancel();
            Console.ReadKey();

        }
    }
}
