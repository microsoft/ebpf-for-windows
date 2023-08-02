using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.IO;
using System.Runtime.Serialization.Json;

namespace Microsoft.WindowsAzure.GuestAgent.Plugins.eBPF.CustomScriptHandler
{
    public class Program
    { 
        const int SCRIPT_TIMEOUT = 20000;
        private static Logger LOGGER;
        private static StatusObj handlerStatus;

        public static void Main(string[] args)
        {
            // deserialize HandlerEnvironment.json
            var handlerEnvironments = DeserializeJsonStringFromFile<List<TopLevelHandlerEnvironment>>(Constants.HandlerEnvironmentFile);
            var rootHandlerEnvironment = handlerEnvironments[0];
            HandlerEnvironment handlerEnvironment = rootHandlerEnvironment.HandlerEnvironment;

            // Setup Logger instance
            if (!Directory.Exists(handlerEnvironment.LogFolder))
            {
                Directory.CreateDirectory(handlerEnvironment.LogFolder);
            }
            string logFile = handlerEnvironment.LogFolder + (handlerEnvironment.LogFolder.EndsWith(@"\") ? "" : @"\") + Constants.HandlerLogFile;
            LOGGER = Logger.GetInstance(logFile);
            LOGGER.LogMessage(string.Format("Starting IaaS Extension '{0}' version '{1}'", Constants.PluginName, rootHandlerEnvironment.Version));
            LOGGER.LogMessage("HandlerEnvironment = " + rootHandlerEnvironment.ToString());

            // handle command-line arguments for installing/enabling/disabling/uninstalling the handler
            string commandName = "None";
            if (args.Count() > 0)
            {
                commandName = args[0];
            }
            HandleCommand(commandName);

            // Setup status file for reporting status
            string statusFile = SetupStatusFile(handlerEnvironment);

            // Report status update
            handlerStatus = new StatusObj()
            {
                Name = Constants.PluginName,
                Code = Constants.StatusCodeOk,
                Operation = string.Format("Done executing {0} Command: '{1}'", Constants.PluginName, commandName),
                Status = StatusEnum.success,
                FormattedMessage = new FormattedMessage()
                {
                    Lang = Constants.Lang_EnUs,
                    Message = "Finished executing command"
                }
            };

            ReportStatus(statusFile, handlerStatus, rootHandlerEnvironment.Version);
        }

        private static void HandleCommand(string commandName)
        {
            if (string.IsNullOrWhiteSpace(commandName))
            {
                LOGGER.Log(LogLevel.Warning, "No command has been specified to execute");
                return;
            }

            LOGGER.Log(LogLevel.Info, "Handling command: '{0}'", commandName);
            if (commandName.Equals("install", StringComparison.InvariantCultureIgnoreCase))
            {
                InstallHandler();
                return;
            }
            else if (commandName.Equals("disable", StringComparison.InvariantCultureIgnoreCase))
            {
                DisableHandler();
                return;
            }
            else if (commandName.Equals("uninstall", StringComparison.InvariantCultureIgnoreCase))
            {
                UninstallHandler();
                return;
            }
            else if (commandName.Equals("update", StringComparison.InvariantCultureIgnoreCase))
            {
                UpdateHandler();
                return;
            }
            else if (commandName.Equals("enable", StringComparison.InvariantCultureIgnoreCase))
            {
                EnableHandler();
                // Mandatory status report
            }
            else
            {
                LOGGER.Log(LogLevel.Warning, "Invalid command: '{0}'", commandName);
            }
        }

        private static string SetupStatusFile(HandlerEnvironment handlerEnvironment)
        {
            // Setup status file for reporting status
            if (!Directory.Exists(handlerEnvironment.StatusFolder))
            {
                Directory.CreateDirectory(handlerEnvironment.StatusFolder);
            }

            // Get sequence number from Status directory
            long sequenceNumber = -1;
            try
            {
                sequenceNumber = GetSequenceNumber(handlerEnvironment.ConfigFolder);
            }
            catch (Exception e)
            {
                LOGGER.Log(LogLevel.Fatal, "Unable to determine sequence number from files in status directory \"{0}\". Exception: {1}", handlerEnvironment.StatusFolder, e);
                Environment.Exit(1);
            }

            string statusFile = handlerEnvironment.StatusFolder + (handlerEnvironment.StatusFolder.EndsWith(@"\") ? "" : @"\") + sequenceNumber + Constants.StatusFileSuffix;
            LOGGER.Log(LogLevel.Warning, "Using status file: '{0}'", statusFile);
            return statusFile;
        }

        private static long GetSequenceNumber(string configDir)
        {
            var dir = new DirectoryInfo(configDir);
            var file = (from f in dir.GetFiles()
                        orderby Convert.ToInt64(Path.GetFileNameWithoutExtension(f.Name)) descending
                        select f).FirstOrDefault();

            long seqNum = 0;
            if (file != null)
            {
                string seqNumStr = file.Name.Substring(0, file.Name.IndexOf('.'));
                long.TryParse(seqNumStr, out seqNum);
            }

            return seqNum;
        }

        /// <summary>
        /// Serializes an object into a JSON-formatted string
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="obj"></param>
        /// <returns>A string with the serialized object "obj"</returns>
        public static string SerializeObjectToJsonString<T>(T obj)
        {
            try
            {
                using (var stream = new MemoryStream())
                {
                    var serializer = new DataContractJsonSerializer(typeof(T));
                    serializer.WriteObject(stream, obj);
                    stream.Position = 0;
                    var streamReader = new StreamReader(stream);
                    return streamReader.ReadToEnd();
                }
            }
            catch (Exception e)
            {
                LOGGER.Log(LogLevel.Error, "Failed to serialize object {0} to JSON string. Exception: {1}", obj, e);
                throw e;
            }
        }

        /// <summary>
        /// Deserializes JSON-formatted data from a file into its respective object
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="fileName"></param>
        /// <returns>Deserialized object of type T, read from file "fileName"</returns>
        public static T DeserializeJsonStringFromFile<T>(string fileName)
        {
            try
            {
                var fileBytes = File.ReadAllBytes(fileName);
                return DeserializeJsonBytes<T>(fileBytes);
            }
            catch (Exception e)
            {
                LOGGER.Log(LogLevel.Error, "Failed to deserialize JSON string from file {0}. Exception: {1}", fileName, e);
                throw e;
            }
        }

        /// <summary>
        /// Deserializes JSON-formatted data from an array of bytes into its respective object
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="bytes"></param>
        /// <returns>Deserialized object of type T, read from an array of bytes</returns>
        /// <exception cref="ArgumentNullException"></exception>
        private static T DeserializeJsonBytes<T>(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes", "Cannot deserialize a null array of bytes");
            }

            using (var stream = new MemoryStream(bytes))
            {
                var serializer = new DataContractJsonSerializer(typeof(T));
                return (T)serializer.ReadObject(stream);
            }
        }

        /// <summary>
        /// Reports the current status of the handler to its respective .status file, 
        /// overwriting the file's current contents.
        /// </summary>
        /// <param name="statusFile">Path + name of the .status file to write to</param>
        /// <param name="statusObj">Status object to write out</param>
        /// <param name="version">Version number of the handler</param>
        private static void ReportStatus(string statusFile, StatusObj statusObj, string version)
        {
            TopLevelStatus rootStatusObj = new TopLevelStatus() { Version = version, TimestampUTC = DateTime.UtcNow, Status = statusObj };
            string rootStatusJson = SerializeObjectToJsonString<List<TopLevelStatus>>(new List<TopLevelStatus>() { rootStatusObj });

            int writeAttempt = 0;
            while (writeAttempt < 3)
            {
                try
                {
                    File.WriteAllText(statusFile, rootStatusJson);
                    return;
                }
                catch (Exception e)
                {
                    writeAttempt++;
                    LOGGER.Log(LogLevel.Warning, "Failed to write status to file \"{0}\". Will retry after {1} seconds. Exception: {2}", statusFile, writeAttempt, e.ToString());
                    Thread.Sleep(1000 * writeAttempt);
                }
            }

            LOGGER.Log(LogLevel.Error, "Failed to write status to file \"{0}\" after {1} attempts", statusFile, writeAttempt);
        }

        /// <summary>
        /// Runs a CMD command
        /// </summary>
        /// <param name="command">Command line to be run through CMD.exe</param>
        /// <param name="timeout">Maximum time alloud for the command execution</param>
        /// <returns>The return code for the the command run</returns>
        private static int RunCmdCommand(string command, int timeout)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c " + command,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            if (process.WaitForExit(timeout))
            {
                return process.ExitCode;
            }
            else
            {
                // Timeout occurred
                process.Kill();
                return -1;
            }
        }

        /// <summary>
        /// Installs the handler
        /// </summary>
        private static void InstallHandler()
        {
            LOGGER.LogMessage("Installing Handler");
            int ret = RunCmdCommand(@"scripts\install.cmd", SCRIPT_TIMEOUT);
            if (ret == 0)
            {
                LOGGER.LogMessage("Handler successfully installed");
            } else {
                LOGGER.Log(LogLevel.Error, "FAILED installing handler -> Error{0}", ret);
            }
        }

        /// <summary>
        /// Enables the handler
        /// </summary>
        private static void EnableHandler()
        {
            LOGGER.LogMessage("Enabling Handler");
            int ret = RunCmdCommand(@"scripts\enable.cmd", SCRIPT_TIMEOUT);
            if (ret == 0)
            {
                LOGGER.LogMessage("Handler successfully enabled");
            }
            else
            {
                LOGGER.Log(LogLevel.Error, "FAILED enabling handler -> Error{0}", ret);
            }
        }

        /// <summary>
        /// Disables the handler
        /// </summary>
        private static void DisableHandler()
        {
            LOGGER.LogMessage("Disabling Handler");
            int ret = RunCmdCommand(@"scripts\disable.cmd", SCRIPT_TIMEOUT);
            if (ret == 0)
            {
                LOGGER.LogMessage("Handler successfully disabled");
            }
            else
            {
                LOGGER.Log(LogLevel.Error, "FAILED disabling handler -> Error{0}", ret);
            }
        }

        /// <summary>
        /// Handles updates to the handler
        /// </summary>
        private static void UpdateHandler()
        {
            LOGGER.LogMessage("Updating Handler");
            int ret = RunCmdCommand(@"scripts\update.cmd", SCRIPT_TIMEOUT);
            if (ret == 0)
            {
                LOGGER.LogMessage("Handler successfully updated");
            }
            else
            {
                LOGGER.Log(LogLevel.Error, "FAILED updating handler -> Error{0}", ret);
            }
        }

        /// <summary>
        /// Uninstalls the handler
        /// </summary>
        private static void UninstallHandler()
        {
            LOGGER.LogMessage("Uninstalling Handler");
            int ret = RunCmdCommand(@"scripts\uninstall.cmd", SCRIPT_TIMEOUT);
            if (ret == 0)
            {
                LOGGER.LogMessage("Handler successfully uninstalled");
            }
            else
            {
                LOGGER.Log(LogLevel.Error, "FAILED uninstalling handler -> Error{0}", ret);
            }
        }
    }
}