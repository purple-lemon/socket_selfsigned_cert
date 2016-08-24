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
        static void Main(string[] args)
        {
            using (var server = new WebSocketEventListener(new IPEndPoint(IPAddress.Any, 8009), new WebSocketListenerOptions() { SubProtocols = new String[] { "123456" }, NegotiationTimeout = TimeSpan.FromSeconds(30) }))
            {

            }
    }
}
