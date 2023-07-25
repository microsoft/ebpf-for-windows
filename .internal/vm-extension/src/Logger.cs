using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Globalization;

namespace Microsoft.WindowsAzure.GuestAgent.Plugins
{
    public enum LogLevel
    {
        Info,
        Warning,
        Error,
        Fatal
    }

    public sealed class Logger
    {
        private static string logFile;
        private static volatile Logger instance;
        private static object syncronizer = new Object();

        private Logger(string logFile)
        {
            Logger.logFile = logFile;
        }

        public static Logger GetInstance(string logFile)
        {
            if (instance == null)
            {
                lock (syncronizer)
                {
                    if (instance == null)
                    {
                        instance = new Logger(logFile);
                    }
                }
            }

            return instance;
        }

        private string ResolveString(LogLevel severityLevel, string formatStr, bool format, params object[] args)
        {
            formatStr = DateTime.UtcNow.ToString("[MM/dd/yyyy HH:mm:ss.ff]", CultureInfo.InvariantCulture.DateTimeFormat) + "\t" + "[" + severityLevel + "]:\t" + formatStr;
            return ((format) ? string.Format(formatStr, args ?? new object[0]) : formatStr) + Environment.NewLine;
        }

        public void Log(LogLevel severityLevel, string formatString, params object[] args)
        {
            string resolvedString = ResolveString(severityLevel, formatString, true, args);
            File.AppendAllText(logFile, resolvedString);
        }

        public void LogMessage(string message)
        {
            string resolvedMessage = ResolveString(LogLevel.Info, message, false);
            File.AppendAllText(logFile, resolvedMessage);

        }
    }
}
