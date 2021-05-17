using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using vtortola.WebSockets;
using vtortola.WebSockets.Rfc6455;

namespace WebSocketEventListenerSample
{
	public class NewExecutionFlow
	{
        public static void Run(X509Certificate2 cert, IPEndPoint endPoint)
        {
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;

            var cancellation = new CancellationTokenSource();

            //var bufferSize = 1024 * 8; // 8KiB
            //var bufferPoolSize = 100 * bufferSize; // 800KiB pool

            var options = new WebSocketListenerOptions
            {
                SubProtocols = new[] { "123456" },
                PingTimeout = TimeSpan.FromSeconds(5),
                NegotiationTimeout = TimeSpan.FromSeconds(30),
                PingMode = PingMode.Manual,
                ParallelNegotiations = 16,
                NegotiationQueueCapacity = 256,
            };
            options.ConnectionExtensions.RegisterSecureConnection(cert);
            options.Standards.RegisterRfc6455(factory =>
            {
                //factory.MessageExtensions.RegisterDeflateCompression();
            });
            // configure tcp transport
            options.Transports.ConfigureTcp(tcp =>
            {
                tcp.BacklogSize = 100; // max pending connections waiting to be accepted
                //tcp.ReceiveBufferSize = bufferSize;
                //tcp.SendBufferSize = bufferSize;
            });

            // adding the WSS extension
            //var certificate = new X509Certificate2(File.ReadAllBytes("<PATH-TO-CERTIFICATE>"), "<PASSWORD>");
            // options.ConnectionExtensions.RegisterSecureConnection(certificate);

            // starting the server
            var server = new WebSocketListener(endPoint, options);

            server.StartAsync().Wait();

            //Console.WriteLine("Echo Server listening: " + string.Join(", ", Array.ConvertAll(endPoint.ToString(), e => e.ToString())) + ".");
            Console.WriteLine("You can test echo server at http://www.websocket.org/echo.html.");

            var acceptingTask = AcceptWebSocketsAsync(server, cancellation.Token);

            Console.WriteLine("Press any key to stop.");
            Console.ReadKey(true);

            Console.WriteLine("Server stopping.");
            cancellation.Cancel();
            server.StopAsync().Wait();
            acceptingTask.Wait();
        }


        private static async Task AcceptWebSocketsAsync(WebSocketListener server, CancellationToken cancellation)
        {
            await Task.Yield();

            while (!cancellation.IsCancellationRequested)
            {
                try
                {
                    var webSocket = await server.AcceptWebSocketAsync(cancellation).ConfigureAwait(false);
                    if (webSocket == null)
                    {
                        if (cancellation.IsCancellationRequested || !server.IsStarted)
                            break; // stopped

                        continue; // retry
                    }

#pragma warning disable 4014
                    EchoAllIncomingMessagesAsync(webSocket, cancellation);
#pragma warning restore 4014
                }
                catch (OperationCanceledException)
                {
                    /* server is stopped */
                    break;
                }
                catch (Exception acceptError)
                {
                    Console.WriteLine("An error occurred while accepting client.", acceptError);
                }
            }

            Console.WriteLine("Server has stopped accepting new clients.");
        }

        private static async Task EchoAllIncomingMessagesAsync(WebSocket webSocket, CancellationToken cancellation)
        {
            Console.WriteLine("Client '" + webSocket.RemoteEndpoint + "' connected.");
            var sw = new Stopwatch();
            try
            {
                while (webSocket.IsConnected && !cancellation.IsCancellationRequested)
                {
                    try
                    {
                        var messageText = await webSocket.ReadStringAsync(cancellation).ConfigureAwait(false);
                        if (messageText == null)
                            break; // webSocket is disconnected

                        sw.Restart();

                        await webSocket.WriteStringAsync(messageText, cancellation).ConfigureAwait(false);

                        Console.WriteLine("Client '" + webSocket.RemoteEndpoint + "' sent: " + messageText + ".");

                        sw.Stop();
                    }
                    catch (TaskCanceledException)
                    {
                        break;
                    }
                    catch (Exception readWriteError)
                    {
                        Console.WriteLine("An error occurred while reading/writing echo message.", readWriteError);
                    }
                }

                // close socket before dispose
                await webSocket.CloseAsync(WebSocketCloseReason.NormalClose);
            }
            finally
            {
                // always dispose socket after use
                webSocket.Dispose();
                Console.WriteLine("Client '" + webSocket.RemoteEndpoint + "' disconnected.");
            }
        }

        private static void TaskScheduler_UnobservedTaskException(object sender, UnobservedTaskExceptionEventArgs e)
        {
            Console.WriteLine("Unobserved Exception: ", e.Exception);
        }
        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            Console.WriteLine("Unhandled Exception: ", e.ExceptionObject as Exception);
        }
    }
}
