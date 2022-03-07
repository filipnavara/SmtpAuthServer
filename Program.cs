using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var listenSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            listenSocket.Bind(new IPEndPoint(IPAddress.Loopback, 8087));

            Console.WriteLine("Listening on port 8087");

            listenSocket.Listen(120);

            while (true)
            {
                var socket = await listenSocket.AcceptAsync();
                _ = ProcessLinesAsync(socket);
            }
        }

        private static string GetString(in ReadOnlySequence<byte> payload, Encoding? encoding = null)
        {
            encoding ??= Encoding.UTF8;
            return payload.IsSingleSegment ? encoding.GetString(payload.FirstSpan)
                : GetStringSlow(payload, encoding);

            static string GetStringSlow(in ReadOnlySequence<byte> payload, Encoding encoding)
            {
                // linearize
                int length = checked((int)payload.Length);
                var oversized = ArrayPool<byte>.Shared.Rent(length);
                try
                {
                    payload.CopyTo(oversized);
                    return encoding.GetString(oversized, 0, length);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(oversized);
                }
            }
        }

        private static async Task ProcessLinesAsync(Socket socket)
        {
            Console.WriteLine($"[{socket.RemoteEndPoint}]: connected");

            // Create a PipeReader over the network stream
            var stream = new NetworkStream(socket);
            var reader = PipeReader.Create(stream);
            var writer = new StreamWriter(stream) { AutoFlush = true };
            var fakeSmtpServer = new FakeSmtpServer();

            fakeSmtpServer.SayHello(writer);

            while (true)
            {
                ReadResult result = await reader.ReadAsync();
                ReadOnlySequence<byte> buffer = result.Buffer;

                while (TryReadLine(ref buffer, out ReadOnlySequence<byte> line))
                {
                    // Process the line.
                    fakeSmtpServer.ProcessLine(GetString(line), writer);
                }

                // Tell the PipeReader how much of the buffer has been consumed.
                reader.AdvanceTo(buffer.Start, buffer.End);

                // Stop reading if there's no more data coming.
                if (result.IsCompleted)
                {
                    break;
                }
            }

            // Mark the PipeReader as complete.
            await reader.CompleteAsync();

            Console.WriteLine($"[{socket.RemoteEndPoint}]: disconnected");
        }

        private static bool TryReadLine(ref ReadOnlySequence<byte> buffer, out ReadOnlySequence<byte> line)
        {
            // Look for a EOL in the buffer.
            SequencePosition? position = buffer.PositionOf((byte)'\n');

            if (position == null)
            {
                line = default;
                return false;
            }

            // Skip the line + the \n.
            line = buffer.Slice(0, position.Value);
            buffer = buffer.Slice(buffer.GetPosition(1, position.Value));
            return true;
        }
    }
}
