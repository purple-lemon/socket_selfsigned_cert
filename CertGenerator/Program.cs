using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CertGenerator
{
	class Program
	{
		static void Main(string[] args)
		{
			var cu = new CertUtils();
			cu.GetCert();
		}
	}
}
