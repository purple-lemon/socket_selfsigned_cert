using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using vtortola.WebSockets;
using WebSocketEventListenerSample;

namespace MoveBall
{
    class Program
    {
        public static List<WebSocket> sockets;
        static void Main(string[] args)
        {
            sockets = new List<WebSocket>();
            using (var server = new WebSocketEventListener(new IPEndPoint(IPAddress.Any, 8001), new WebSocketListenerOptions() { SubProtocols = new String[] { "123456" }, NegotiationTimeout = TimeSpan.FromSeconds(30) }))
            {
				SetEvents(server);
                server.Start();
                Console.ReadKey(true);
                Console.ReadKey(true);
            }
        }

        public static void SetEvents(WebSocketEventListener server)
        {
            server.OnConnect += (ws) => {
                sockets.Add(ws);
                Console.WriteLine("Connection from " + ws.RemoteEndpoint.ToString());
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
                Console.WriteLine("Message from [" + ws.RemoteEndpoint + "]: " + msg);
                var wsContext = ws;
                //var task = Task.Factory.StartNew(() =>
                //{
                    var util = new Utils();
                    // util.ProcessMessage(wsContext);
                    foreach (var w in sockets)
                    {
                        if (w != ws)
                        {
                            w.WriteString(msg);
                        }
                    }
                //});
            };
        }
    }
}
