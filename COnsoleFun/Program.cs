using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace COnsoleFun
{
	class Program
	{
		static void Main(string[] args)
		{
			var clearCacheText = @"@echo off

			set ChromeDir=C:\Users\%USERNAME%\appdata\Local\Google\Chrome\User Data\Default\Cache

			del /q /s /f "" % ChromeDir % ""
			rd / s / q ""%ChromeDir%""";
			var fInfo = new FileInfo("ClearChromeCache.bat");
			if (!fInfo.Exists)
			{
				File.WriteAllText("ClearChromeCache.bat", clearCacheText);
			}

			Process proc = null;
			try
			{
				proc = new Process();
				proc.StartInfo.FileName = "ClearChromeCache.bat";
				proc.StartInfo.CreateNoWindow = false;
				proc.Start();
				proc.WaitForExit();
			}
			catch (Exception ex)
			{
				Console.WriteLine("Exception Occurred :{0},{1}", ex.Message, ex.StackTrace.ToString());
			}
		}

	}
}
