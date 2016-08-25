using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using vtortola.WebSockets;
using WebSocketEventListenerSample;

namespace ChatExample
{
    class Program
    {
        public static List<WebSocket> sockets;
        public static Dictionary<string, string> names;
        static void Main(string[] args)
        {
            sockets = new List<WebSocket>();
			names = new Dictionary<string, string>();
			using (var server = new WebSocketEventListener(new IPEndPoint(IPAddress.Any, 8002), new WebSocketListenerOptions() { SubProtocols = new String[] { "123456" }, NegotiationTimeout = TimeSpan.FromSeconds(30) }))
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
                var wsContext = ws;
                Console.WriteLine("Message from [" + ws.RemoteEndpoint + "]: " + msg);
                var msgData = msg.Split(":".ToArray(), StringSplitOptions.RemoveEmptyEntries)[1];
                var msgToSend = string.Empty;
                if (msg.StartsWith("Name"))
                {
                    names.Add(ws.RemoteEndpoint.ToString(), msgData);
                    msgToSend = ComposeMsg(names[ws.RemoteEndpoint.ToString()], "Joined");
                }
                else
                {
                    msgToSend = ComposeMsg(names[ws.RemoteEndpoint.ToString()], msgData);
                }
                
                //var task = Task.Factory.StartNew(() =>
                //{
                // util.ProcessMessage(wsContext);
                foreach (var w in sockets)
                {
                    if (w != ws)
                    {
                        w.WriteString(msgToSend);
                    }
                }
                //});
            };
        }

        public static string ComposeMsg(string name, string msg)
        {
            return $"<div><strong>{name}</strong><span>  {msg}</span></div>";
        }
    }
}
