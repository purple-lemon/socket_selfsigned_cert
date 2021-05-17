using System;
using System.Collections.Generic;
using System.Data;
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
		public static DataTable table;
		public static DataTable Table
		{
			get
			{
				return table = table ?? new DataTable("MyTable" + DateTime.Now.Ticks);
			}
		}
        static async Task Main(string[] args)
        {
			//CheckTask();
			//return;
			//var k1 = Table;
			//var k2 = Table;

			var tokenSource = new CancellationTokenSource();
			var token = tokenSource.Token;
			var r = new Random();
			var utils = new Utils();
			var cert = utils.GetCert();
			var sockets = new List<WebSocket>();

            NewExecutionFlow.Run(cert, new IPEndPoint(IPAddress.Any, 8009));

            return;


            using (var server = new WebSocketEventListener(new IPEndPoint(IPAddress.Any, 8009), new WebSocketListenerOptions() { SubProtocols = new String[] { "123456" }, NegotiationTimeout = TimeSpan.FromSeconds(30) },cert))
            {
                server.OnConnect += (ws) => {
                    sockets.Add(ws);
                    Console.WriteLine("Connection from " + ws.RemoteEndpoint.ToString());
					var socket = ws;
					Task.Factory.StartNew(() =>
					{
						while (ws.IsConnected)
						{

							Thread.Sleep(1000);
							ws.WriteStringAsync(DateTime.Now.ToString());
						}
					});
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
                                    w.WriteStringAsync("new guy connected").RunSynchronously();
                                }
                            }
                        }, token);
                        
                        //ws.WriteStringAsync(new String(msg.Reverse().ToArray()), CancellationToken.None).Wait();
                    };

                await server.Start();
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
