using Reqnroll;

namespace OpenCertServer.Testing;

[Binding]
public sealed class ContainerTestRunHooks
{
    private static FileStream? _lease;

    [BeforeTestRun(Order = int.MinValue)]
    public static async Task AcquireAsync()
    {
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".opencertserver-container-tests.lock");
        var reported = false;
        while (true)
        {
            try
            {
                _lease = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                return;
            }
            catch (IOException exception) when ((exception.HResult & 0xffff) is 11 or 32 or 33 or 35)
            {
                if (!reported)
                {
                    Console.Error.WriteLine($"Waiting for another OpenCertServer container test run: {path}");
                    reported = true;
                }

                await Task.Delay(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            }
            catch (IOException exception)
            {
                Console.Error.WriteLine($"Unable to acquire container test lease (0x{exception.HResult:X8}): {exception.Message}");
                throw;
            }
        }
    }

    [AfterTestRun(Order = int.MaxValue)]
    public static void Release()
    {
        _lease?.Dispose();
        _lease = null;
    }
}
